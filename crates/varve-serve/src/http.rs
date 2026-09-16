//! The smallest HTTP/1.1 server that can serve a document, written against
//! `std::net` (REQ-LAYERDOCS-001).
//!
//! **Why this is a separate program at all.** `varve` is the binary that
//! decides whether a toolchain can be trusted. Giving it a listening socket
//! widens the surface of exactly the thing whose smallness is the argument.
//! So the viewer ships beside it — one repository, one release, one signature,
//! and a realm may carry it or not.
//!
//! **Why path traversal cannot happen here.** The pages are served out of the
//! archive **in memory**; this program never opens a file in response to a
//! request. A request path either matches a member of the verified payload or
//! it does not, so there is no filesystem path to escape and no `..` to
//! normalise. That is a property of the design rather than of the care taken
//! in one function — which is the kind of guarantee worth choosing, because it
//! cannot be lost by a later edit that forgets the rule.
//!
//! **Loopback only.** The listener binds `127.0.0.1`, never `0.0.0.0`. A
//! document is a local artefact; serving a customer's pinned documentation to
//! their whole network by default would be a surprising thing for a tool like
//! this to do.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};

/// The document, indexed once and held in memory.
///
/// Read ONCE at startup rather than per request. A `.tar.gz` is sequential, so
/// a request-time read would decompress the whole archive for every page — the
/// cost noted in `varve-core::docsexport`, which is free at a megabyte and
/// unacceptable for rustdoc.
pub struct Site {
    pub pages: BTreeMap<String, Vec<u8>>,
    /// Where `/` sends a reader, from the SIGNED `docs-entry` annotation.
    pub entry: Option<String>,
    pub label: String,
}

impl Site {
    /// The bytes for a request path, if the document has that page.
    pub fn page(&self, path: &str) -> Option<&Vec<u8>> {
        self.pages.get(path.trim_start_matches('/'))
    }
}

/// Content types by extension.
///
/// Wrong here is not cosmetic: a stylesheet served as `text/plain` is ignored
/// by the browser and the document renders unstyled, which reads as "varve
/// broke the docs" rather than as a header problem. The list covers what
/// rustdoc and a generated HTML bundle actually contain.
pub fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "txt" | "md" => "text/plain; charset=utf-8",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// The path a request line asks for, without the query string.
///
/// Returns `None` for anything that is not a `GET`, so the server answers 405
/// rather than guessing. `HEAD` is deliberately not special-cased: a browser
/// reading a local document does not need it, and every branch here is code
/// inside a process that accepts connections.
pub fn requested_path(request_line: &str) -> Option<String> {
    let mut parts = request_line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    let path = target.split('?').next().unwrap_or(target);
    Some(percent_decode(path))
}

/// Decode `%XX` escapes. rustdoc emits paths with `%20` and friends, and a
/// page whose name contains a space is otherwise unreachable.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn respond(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()
}

/// What a request resolves to, decided WITHOUT touching the socket.
///
/// Split from the writing half deliberately. The decision — is this a GET, does
/// `/` have an entry to go to, does the document contain the page — is the part
/// worth testing, and a function that also owns a `TcpStream` can only be
/// tested by opening one. Mutation testing made the cost concrete: every
/// mutant inside the combined function survived, because nothing called it.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Serve this page of the document.
    Page(String),
    /// Not a GET.
    MethodNotAllowed,
    /// `/` was asked for and the document declares no entry.
    NoEntryPoint,
    /// The document does not contain it.
    Missing(String),
}

/// Decide what a request line means for this document.
pub fn resolve_request(site: &Site, request_line: &str) -> Resolution {
    let Some(path) = requested_path(request_line) else {
        return Resolution::MethodNotAllowed;
    };
    // `/` goes to the entry the manifest DECLARED, not to whatever index.html
    // happens to be nearest. That declaration was checked at deposit, so it is
    // known to exist.
    let resolved = if path == "/" || path.is_empty() {
        match &site.entry {
            Some(e) => e.clone(),
            None => return Resolution::NoEntryPoint,
        }
    } else {
        path
    };
    // One spelling, always store-relative. The entry comes from the manifest
    // without a leading slash and a request comes with one; letting both reach
    // the caller would mean `Page` sometimes carries `/a/b.css` and sometimes
    // `a/b.css`, and the next person to match on it would pick whichever they
    // happened to see first.
    let resolved = resolved.trim_start_matches('/').to_string();
    if site.page(&resolved).is_some() {
        Resolution::Page(resolved)
    } else {
        Resolution::Missing(resolved)
    }
}

fn handle(site: &Site, stream: &mut TcpStream) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(&*stream).read_line(&mut line)?;
    match resolve_request(site, &line) {
        Resolution::Page(p) => {
            let bytes = site.page(&p).expect("resolve_request said it is present");
            respond(stream, "200 OK", content_type(&p), bytes)
        }
        Resolution::MethodNotAllowed => respond(
            stream,
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            b"this serves a document; only GET is answered\n",
        ),
        Resolution::NoEntryPoint => respond(
            stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"this document declares no entry point\n",
        ),
        Resolution::Missing(p) => respond(
            stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            format!(
                "{} does not contain {p}\n\nThis is the document varve verified; a missing \
                 page means the payload does not have it, not that a file could not be \
                 read.\n",
                site.label
            )
            .as_bytes(),
        ),
    }
}

/// Serve until interrupted. Returns the bound port, then blocks.
pub fn serve(site: &Site, port: u16) -> anyhow::Result<()> {
    let listener = bind(port)?;
    println!(
        "  http://127.0.0.1:{}  — ctrl-c to stop",
        listener.local_addr()?.port()
    );
    accept_loop(site, &listener)
}

/// Bind loopback. Separated so a test can take the port before serving.
pub fn bind(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, port))
}

/// Answer connections until the listener dies.
pub fn accept_loop(site: &Site, listener: &TcpListener) -> anyhow::Result<()> {
    for stream in listener.incoming() {
        let mut stream = stream?;
        // One bad connection is not a reason to stop serving a document.
        if let Err(e) = handle(site, &mut stream) {
            eprintln!("  (connection error: {e})");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stylesheet served as text/plain is ignored by the browser and the
    /// document renders unstyled — which reads as varve breaking the docs.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn the_types_a_generated_bundle_actually_contains_are_known() {
        assert_eq!(content_type("a/b.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("m.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("i.svg"), "image/svg+xml");
        assert_eq!(content_type("f.woff2"), "font/woff2");
        assert_eq!(content_type("p.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("d.pdf"), "application/pdf");
        assert_eq!(content_type("m.wasm"), "application/wasm");
        assert_eq!(content_type("r.md"), "text/plain; charset=utf-8");
        assert_eq!(content_type("i.png"), "image/png");
        assert_eq!(content_type("j.jpeg"), "image/jpeg");
        assert_eq!(content_type("f.ico"), "image/x-icon");
        assert_eq!(content_type("s.json"), "application/json");
        assert_eq!(content_type("a.gif"), "image/gif");
        assert_eq!(content_type("b.webp"), "image/webp");
        assert_eq!(content_type("c.woff"), "font/woff");
        assert_eq!(content_type("d.ttf"), "font/ttf");
        assert_eq!(content_type("e.htm"), "text/html; charset=utf-8");
        assert_eq!(content_type("f.mjs"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("g.jpg"), "image/jpeg");
        assert_eq!(content_type("h.txt"), "text/plain; charset=utf-8");
        // Unknown stays a download rather than being guessed as text.
        assert_eq!(content_type("x.bin"), "application/octet-stream");
        assert_eq!(content_type("noextension"), "application/octet-stream");
    }

    /// The pages live in memory and a request is a MAP LOOKUP, so traversal is
    /// not defended against — it is impossible. Asserted so that a later change
    /// to serving from disk has to break this test first.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn a_traversal_request_is_simply_a_miss() {
        let mut pages = BTreeMap::new();
        pages.insert("index.html".to_string(), b"root".to_vec());
        let site = Site {
            pages,
            entry: Some("index.html".into()),
            label: "t".into(),
        };
        assert!(site.page("/index.html").is_some());
        for escape in [
            "/../../../../etc/passwd",
            "/..%2f..%2fetc/passwd",
            "//etc/passwd",
        ] {
            assert!(
                site.page(escape).is_none(),
                "{escape} resolved to a page; it must simply not be in the map"
            );
        }
    }

    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn only_get_is_answered_and_the_query_string_is_not_part_of_the_path() {
        assert_eq!(
            requested_path("GET /a/b.html HTTP/1.1"),
            Some("/a/b.html".into())
        );
        assert_eq!(
            requested_path("GET /search.html?q=Store HTTP/1.1"),
            Some("/search.html".into())
        );
        assert_eq!(requested_path("POST /a HTTP/1.1"), None);
        assert_eq!(requested_path("DELETE / HTTP/1.1"), None);
    }

    fn site() -> Site {
        let mut pages = BTreeMap::new();
        pages.insert("index.html".to_string(), b"<h1>root</h1>".to_vec());
        pages.insert("a/b.css".to_string(), b"body{}".to_vec());
        Site {
            pages,
            entry: Some("index.html".into()),
            label: "The handbook".into(),
        }
    }

    /// `/` goes to the DECLARED entry, not to a guess, and each other outcome
    /// is distinct. Every mutant inside the old combined handler survived
    /// because nothing could call it; this is the decision, callable.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn each_request_outcome_is_distinct() {
        let s = site();
        assert_eq!(
            resolve_request(&s, "GET / HTTP/1.1"),
            Resolution::Page("index.html".into()),
            "`/` must go to the declared entry"
        );
        assert_eq!(
            resolve_request(&s, "GET /a/b.css HTTP/1.1"),
            Resolution::Page("a/b.css".into())
        );
        assert_eq!(
            resolve_request(&s, "GET /nope.html HTTP/1.1"),
            Resolution::Missing("nope.html".into())
        );
        assert_eq!(
            resolve_request(&s, "POST / HTTP/1.1"),
            Resolution::MethodNotAllowed
        );
    }

    /// A document with no declared entry must say so, not serve something.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn no_declared_entry_is_reported_rather_than_guessed() {
        let mut s = site();
        s.entry = None;
        assert_eq!(
            resolve_request(&s, "GET / HTTP/1.1"),
            Resolution::NoEntryPoint
        );
        // …but a named page still resolves; the absence only affects `/`.
        assert_eq!(
            resolve_request(&s, "GET /index.html HTTP/1.1"),
            Resolution::Page("index.html".into())
        );
    }

    /// The whole path, over a real socket: bind, connect, read the response.
    /// Nothing else exercises the writing half, and "the server answers" is
    /// not provable by reading the code.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn a_real_request_over_loopback_gets_the_document() {
        use std::io::Read;
        let listener = bind(0).expect("loopback binds");
        let port = listener.local_addr().expect("addr").port();
        let s = site();
        std::thread::spawn(move || {
            // One connection is enough for this test; take it and answer.
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = handle(&s, &mut stream);
            }
        });

        let mut c = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .expect("writes");
        let mut got = String::new();
        c.read_to_string(&mut got).expect("reads");

        assert!(got.starts_with("HTTP/1.1 200 OK"), "{got}");
        assert!(got.contains("Content-Type: text/html"), "{got}");
        assert!(got.contains("Content-Length: 13"), "{got}");
        assert!(got.ends_with("<h1>root</h1>"), "{got}");
    }

    /// It binds loopback, never the network — the one property a reader of the
    /// security topic is entitled to rely on.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn it_binds_loopback_only() {
        let l = bind(0).expect("binds");
        assert_eq!(
            l.local_addr().expect("addr").ip(),
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            "a document must not be served to the network by default"
        );
    }

    /// rustdoc emits escaped paths; a page with a space in its name is
    /// otherwise unreachable.
    // rivet: verifies REQ-LAYERDOCS-001
    #[test]
    fn percent_escapes_are_decoded() {
        assert_eq!(percent_decode("/a%20b.html"), "/a b.html");
        assert_eq!(percent_decode("/plain.html"), "/plain.html");
        // A malformed escape is left alone rather than dropped.
        assert_eq!(percent_decode("/a%zz"), "/a%zz");
        // A truncated escape at the very end must not read past the string.
        assert_eq!(percent_decode("/a%2"), "/a%2");
        assert_eq!(percent_decode("/a%"), "/a%");
        // Consecutive escapes, so an off-by-one in the cursor shows up.
        assert_eq!(percent_decode("%41%42%43"), "ABC");
        assert_eq!(percent_decode(""), "");
    }
}
