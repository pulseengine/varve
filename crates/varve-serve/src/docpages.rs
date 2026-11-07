//! The members of a verified docs payload, as pages with titles.
//!
//! Everything comes out of the payload's own archive, read through
//! `varve-core`: a stray file planted in the store is not a member and never
//! appears, and a tampered archive was already refused when the layer
//! verified (REQ-AGENTDOCS-002 clause 2).

use varve_core::docsexport::{DocsPayload, members_of};
use varve_core::sdkexport::MemberBody;

/// One page of a docs payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The member path, without a leading `./`.
    pub path: String,
    pub title: String,
    /// The page's text, for ranking only (REQ-AGENTDOCS-005): never printed.
    pub text: String,
}

/// How much of a page is read to find its title.
const TITLE_WINDOW: usize = 8192; // 8 KiB

/// How many bytes of one page are searched. The payload does not cap a
/// page, and a question must not cost more for a larger page without limit;
/// the rest of a page past this is not searched (it is still readable with
/// `page`).
pub const TEXT_WINDOW: usize = 512 * 1024; // 512 KiB

/// The text of one page that a question is matched against: Markdown as it
/// is, HTML with markup, script and style removed and entities decoded. When
/// an HTML page has a `<main>` element (rustdoc does) only its content is
/// searched, so the sidebar listing every item of the crate, repeated on
/// every page, does not make every page match every item name.
pub fn search_text(path: &str, bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(TEXT_WINDOW)]).into_owned();
    if path.to_ascii_lowercase().ends_with(".md") {
        return text;
    }
    html_text(main_content(&text))
}

/// The inside of the first `<main ...>` element, to its close or the end of
/// the text; the whole text when there is none.
fn main_content(html: &str) -> &str {
    let lower = html.to_ascii_lowercase();
    for (at, _) in lower.match_indices("<main") {
        // `<mainframe>` is not `<main>`
        if !matches!(
            lower.as_bytes().get(at + 5),
            Some(b'>' | b' ' | b'\t' | b'\n' | b'\r')
        ) {
            continue;
        }
        let Some(open_end) = lower[at..].find('>') else {
            return "";
        };
        let start = at + open_end + 1;
        let end = lower[start..]
            .find("</main")
            .map_or(html.len(), |e| start + e);
        return &html[start..end];
    }
    html
}

fn decode_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn is_page(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".html") || lower.ends_with(".htm") || lower.ends_with(".md")
}

/// rustdoc ships its sources, its search machinery and its static assets in
/// the same tree; none of them answers a question.
fn is_noise(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or("");
    let file = path.rsplit('/').next().unwrap_or("");
    matches!(first, "src" | "static.files") || file.starts_with("search")
}

/// A page's title: its `<title>`, else a Markdown `# ` heading, else its path.
pub fn title_of(path: &str, bytes: &[u8]) -> String {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(TITLE_WINDOW)]).into_owned();
    let lower = head.to_ascii_lowercase();
    if let (Some(a), Some(b)) = (lower.find("<title>"), lower.find("</title>"))
        && a + 7 <= b
    {
        let t = crate::help::clean(&decode_entities(&head[a + 7..b]));
        if !t.is_empty() {
            return t;
        }
    }
    if let Some(h) = head.lines().find_map(|l| l.strip_prefix("# ")) {
        let t = crate::help::clean(h);
        if !t.is_empty() {
            return t;
        }
    }
    path.to_string()
}

/// Every page of a TREE payload, sorted by path. Single-file formats have no
/// pages.
pub fn pages(payload: &DocsPayload) -> anyhow::Result<Vec<Page>> {
    if !payload.format.is_tree() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for m in members_of(payload).map_err(|e| anyhow::anyhow!(e.to_string()))? {
        let MemberBody::File { bytes, .. } = m.body else {
            continue;
        };
        let path = m.path.trim_start_matches("./").to_string();
        if is_page(&path) && !is_noise(&path) {
            out.push(Page {
                title: title_of(&path, &bytes),
                text: search_text(&path, &bytes),
                path,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    Ok(out)
}

/// Markup removed, scripts and styles dropped, entities decoded.
pub fn html_text(html: &str) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(open) = rest.find('<') {
        out.push_str(&rest[..open]);
        let after = &rest[open..];
        let lower: String = after
            .chars()
            .take(8)
            .collect::<String>()
            .to_ascii_lowercase();
        let skip_to = if lower.starts_with("<script") {
            Some("</script>")
        } else if lower.starts_with("<style") {
            Some("</style>")
        } else {
            None
        };
        if let Some(end_tag) = skip_to {
            let l = after.to_ascii_lowercase();
            rest = l.find(end_tag).map_or("", |e| &after[e + end_tag.len()..]);
            continue;
        }
        let Some(close) = after.find('>') else {
            rest = "";
            break;
        };
        out.push(' ');
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    decode_entities(&out)
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// One member of a verified payload, as text. `None` when the payload has no
/// such member — including every `../` path, which can never equal a member
/// name, so there is nothing to defend.
pub fn read_page(payload: &DocsPayload, path: &str) -> anyhow::Result<Option<String>> {
    let want = path.trim_start_matches("./");
    for m in members_of(payload).map_err(|e| anyhow::anyhow!(e.to_string()))? {
        let MemberBody::File { bytes, .. } = m.body else {
            continue;
        };
        if m.path.trim_start_matches("./") == want {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            return Ok(Some(if path.to_ascii_lowercase().ends_with(".md") {
                text
            } else if is_page(path) {
                html_text(&text)
            } else {
                text
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use varve_core::layerspec::DocsFormat;

    use crate::fixture;

    fn payload(format: DocsFormat, files: &[(&str, &str)]) -> DocsPayload {
        DocsPayload {
            name: "doc".into(),
            version: "1.0.0".into(),
            format,
            entry: None,
            title: None,
            documents: None,
            bytes: fixture::tar_gz(files),
        }
    }

    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn a_title_is_the_title_element_a_heading_or_the_path() {
        let html = b"<html><head><TITLE>Store &amp; co in a::b - Rust</TITLE></head>";
        assert_eq!(title_of("x.html", html), "Store & co in a::b - Rust");
        assert_eq!(
            title_of("x.md", b"intro\n# The Heading\nbody"),
            "The Heading"
        );
        assert_eq!(title_of("a/b.html", b"<p>no title</p>"), "a/b.html");
        assert_eq!(title_of("a.html", b"<title></title>"), "a.html");
        assert_eq!(title_of("a.html", b"</title><title>"), "a.html");
        // the window: a title past 8 KiB is not found
        let late = format!("{}<title>late</title>", " ".repeat(TITLE_WINDOW));
        assert_eq!(title_of("late.html", late.as_bytes()), "late.html");
        let edge = format!("{}<title>t</title>", " ".repeat(TITLE_WINDOW - 16));
        assert_eq!(title_of("e.html", edge.as_bytes()), "t");
    }

    /// Pages are html and markdown members; rustdoc's sources, search and
    /// assets are not pages; a PDF has none.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn pages_are_the_members_that_answer_questions() {
        let p = payload(
            DocsFormat::Rustdoc,
            &[
                ("c/index.html", "<title>c - Rust</title>"),
                ("c/struct.Store.html", "<title>Store in c - Rust</title>"),
                ("c/notes.md", "# Notes"),
                ("src/c/lib.rs.html", "<title>lib.rs</title>"),
                ("static.files/x.html", "<title>asset</title>"),
                ("c/search.html", "<title>search</title>"),
                ("c/data.json", "{}"),
            ],
        );
        let got: Vec<(String, String)> = pages(&p)
            .unwrap()
            .into_iter()
            .map(|g| (g.path, g.title))
            .collect();
        assert_eq!(
            got,
            [
                ("c/index.html".into(), "c - Rust".into()),
                ("c/notes.md".into(), "Notes".into()),
                ("c/struct.Store.html".into(), "Store in c - Rust".into()),
            ]
        );
        let pdf = payload(DocsFormat::Pdf, &[("a.html", "<title>x</title>")]);
        assert!(pages(&pdf).unwrap().is_empty());
        assert!(is_page("A.HTML") && is_page("a.htm") && is_page("a.md") && !is_page("a.txt"));
        assert!(is_noise("src/a") && is_noise("a/search-index.js") && !is_noise("a/src/b"));
    }

    /// Script and style are dropped whole, tags become spaces, entities decode.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn html_becomes_text() {
        let h = "<h1>Hi &amp; bye</h1><SCRIPT>var x = '<b>';</SCRIPT><p>a<b>b</b></p><style>p{}</style>\n\n<p>end";
        assert_eq!(html_text(h), "Hi & bye a b\nend");
        assert_eq!(html_text("a < b"), "a");
        assert_eq!(html_text("plain"), "plain");
        assert_eq!(html_text("x<script>never closed"), "x");
    }

    /// What a question is matched against: markdown as written; HTML as text
    /// from its `<main>` when it has one; a bounded prefix of a huge page.
    // rivet: verifies REQ-AGENTDOCS-005
    #[test]
    fn search_text_is_markdown_or_the_main_content_of_html_within_a_window() {
        assert_eq!(search_text("a.md", b"# T\n<b>x</b>"), "# T\n<b>x</b>");
        assert_eq!(search_text("A.MD", b"<i>"), "<i>");
        assert_eq!(search_text("a.html", b"<p>a<b>b</b></p>"), "a b");
        let rd = b"<nav>side</nav><MAIN id=x><p>body &amp; soul</p></MAIN><footer>foot</footer>";
        assert_eq!(search_text("a.html", rd), "body & soul");
        // newline and tab also end the tag name; an unclosed main runs to the end
        assert_eq!(search_text("a.html", b"<nav>n</nav><main\n>in"), "in");
        assert_eq!(search_text("a.html", b"<nav>n</nav><main\t>in"), "in");
        assert_eq!(search_text("a.html", b"<nav>n</nav><main>in</main"), "in");
        // `<mainframe>` is not main; a later real <main> is found
        assert_eq!(search_text("a.html", b"<mainframe>x</mainframe>"), "x");
        assert_eq!(
            search_text("a.html", b"<mainframe>x</mainframe><main>y</main>"),
            "y"
        );
        // a main that never closes its tag has no content
        assert_eq!(search_text("a.html", b"<p>a</p><main id=x"), "");
        // the window: bytes past it are not searched, and cutting inside a
        // multi-byte character does not panic
        let mut big = "a ".repeat(TEXT_WINDOW / 2).into_bytes();
        big.extend_from_slice(b"beyondwindow");
        assert!(!search_text("a.md", &big).contains("beyondwindow"));
        let mut edge = vec![b'x'; TEXT_WINDOW - 2];
        edge.extend_from_slice(" tail".as_bytes());
        assert_eq!(search_text("a.md", &edge).len(), TEXT_WINDOW);
        assert_eq!(TEXT_WINDOW, 524_288, "the documented 512 KiB cap");
        let mut cut = vec![b'x'; TEXT_WINDOW - 1];
        cut.extend_from_slice("é".as_bytes());
        assert!(search_text("a.md", &cut).starts_with("xxx"));
    }

    /// Pages carry their text, so the index can rank by it.
    // rivet: verifies REQ-AGENTDOCS-005
    #[test]
    fn pages_carry_their_search_text() {
        let p = payload(
            DocsFormat::Html,
            &[
                ("a.html", "<title>T</title><main>hello</main>"),
                ("b.md", "# B\nworld"),
            ],
        );
        let got: Vec<(String, String)> = pages(&p)
            .unwrap()
            .into_iter()
            .map(|g| (g.path, g.text))
            .collect();
        assert_eq!(
            got,
            [
                ("a.html".into(), "hello".into()),
                ("b.md".into(), "# B\nworld".into())
            ]
        );
    }

    /// `page` shows a member, refuses everything else — `../` included.
    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn only_members_of_the_payload_can_be_read() {
        let p = payload(
            DocsFormat::Html,
            &[
                ("index.html", "<p>hello <b>world</b></p>"),
                ("n.md", "# raw *md*"),
                ("d/x.txt", "plain"),
            ],
        );
        assert_eq!(
            read_page(&p, "index.html").unwrap().as_deref(),
            Some("hello world")
        );
        assert_eq!(
            read_page(&p, "./index.html").unwrap().as_deref(),
            Some("hello world")
        );
        assert_eq!(
            read_page(&p, "n.md").unwrap().as_deref(),
            Some("# raw *md*")
        );
        assert_eq!(read_page(&p, "d/x.txt").unwrap().as_deref(), Some("plain"));
        for bad in [
            "../index.html",
            "d/../index.html",
            "missing.html",
            "/etc/passwd",
            "",
        ] {
            assert_eq!(read_page(&p, bad).unwrap(), None, "{bad}");
        }
    }
}
