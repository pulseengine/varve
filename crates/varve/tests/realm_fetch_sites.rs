//! REQ-MIRROR-002 clause 5: no realm fetch site may build its source from the
//! realm's primary alone.
//!
//! `Realm::sources` is the primary followed by its mirrors. A fetch that reads
//! `realm.registry` (or builds a `RegistrySource` / `DirSource` /
//! `OciLayoutSource` by hand) decides on the primary alone, so a down primary
//! fails a realm that declares working mirrors — which is exactly how
//! `mirrors` came to be parsed and never used.
//!
//! The scan is over production code in `crates/*/src`: every item gated by
//! `#[cfg(test)]` is blanked by brace matching (so a test module early in a
//! file does not hide the production code after it), and comments are skipped.
//! A hit is allowed only if it matches an entry below, and every entry states
//! why that site is not a realm fetch.

use std::path::{Path, PathBuf};

/// What a fetch site must not contain outside the allowlist.
///
/// `realm.registry` also matches `m.realm.registry` and `ctx.realm.registry`;
/// `r.registry` is the shape a short binding of a `Realm` takes.
const FORBIDDEN: &[&str] = &[
    "realm.registry",
    "r.registry",
    "sources[0]",
    "sources.first()",
    "RegistrySource::parse(",
    "RegistrySource::new(",
    "DirSource::at(",
    "OciLayoutSource::at(",
];

/// (file suffix, a substring of the allowed line, why it is not a realm fetch).
/// Each entry names the specific line it allows, so an unrelated new use in
/// the same file is still refused.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "varve-core/src/mirror.rs",
        "let mut registry = crate::RegistrySource::parse(spec)?;",
        "`build_source`, the one place that turns a realm's source STRINGS into \
         sources, called once per entry of `realm.sources` in order",
    ),
    (
        "varve-core/src/mirror.rs",
        "crate::OciLayoutSource::at(path).for_platform(platform)",
        "`build_source`: the local OCI-layout shape of one entry of `realm.sources`",
    ),
    (
        "varve-core/src/mirror.rs",
        "Ok(Box::new(crate::DirSource::at(path)))",
        "`build_source`: the local directory shape of one entry of `realm.sources`",
    ),
    (
        "varve-core/src/mirror.rs",
        ".map(|r| r.registry)",
        "reads the HOST out of an already-parsed RegistryRef so mirrors on other \
         hosts can be credential-restricted; not a Realm, not a fetch",
    ),
    (
        "varve-core/src/mirror.rs",
        "sources.first().and_then(|p| registry_host(p))",
        "reads only the primary's HOST, to decide which mirrors are on another \
         host; every source (primary included) is still built from the whole list",
    ),
    (
        "varve-core/src/layerspec.rs",
        "registry: m.realm.registry.clone()",
        "PUBLISHING side: copies the producer manifest's registry into the \
         assembler's VARVE_REGISTRY, the place a deposit is pushed to. Pushing \
         goes to the primary; a mirror is a read-only copy",
    ),
    (
        "varve-producer/src/main.rs",
        "m.realm.registry.trim_start_matches",
        "PUBLISHING side: carry-forward reuse pulls blobs the producer itself \
         previously pushed to its primary (via oras, digest-checked) so it can \
         republish them; the primary is the producer's own write target and a \
         lagging mirror would only cause needless re-downloads",
    ),
    (
        "varve-producer/src/main.rs",
        "RegistrySource::parse(&m.realm.registry)",
        "PUBLISHING side: `advisories` reads back what the producer itself \
         published to its primary to decide what to draft; every result is \
         re-verified there, and the draft is pushed to the primary",
    ),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().filter_map(Result::ok) {
        let p = entry.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Lexer state that survives a line break.
#[derive(Default)]
struct Lex {
    /// Inside a `"..."` string.
    in_str: bool,
    /// Inside a raw string closed by `"` plus this many `#`.
    raw: Option<usize>,
    /// Block-comment nesting depth.
    block: usize,
}

impl Lex {
    /// Net `{`/`}` on this line, ignoring braces in strings, chars, comments.
    fn braces(&mut self, line: &str) -> (i32, i32) {
        let b: Vec<char> = line.chars().collect();
        let (mut open, mut close) = (0, 0);
        let mut i = 0;
        while i < b.len() {
            let c = b[i];
            if self.block > 0 {
                if c == '*' && b.get(i + 1) == Some(&'/') {
                    self.block -= 1;
                    i += 2;
                } else if c == '/' && b.get(i + 1) == Some(&'*') {
                    self.block += 1;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if let Some(h) = self.raw {
                if c == '"' && b[i + 1..].iter().take(h).filter(|x| **x == '#').count() == h {
                    self.raw = None;
                    i += 1 + h;
                } else {
                    i += 1;
                }
                continue;
            }
            if self.in_str {
                if c == '\\' {
                    i += 2;
                } else {
                    if c == '"' {
                        self.in_str = false;
                    }
                    i += 1;
                }
                continue;
            }
            match c {
                '/' if b.get(i + 1) == Some(&'/') => break,
                '/' if b.get(i + 1) == Some(&'*') => {
                    self.block = 1;
                    i += 2;
                }
                'r' if matches!(b.get(i + 1), Some('"' | '#')) => {
                    let hashes = b[i + 1..].iter().take_while(|x| **x == '#').count();
                    if b.get(i + 1 + hashes) == Some(&'"') {
                        self.raw = Some(hashes);
                        i += 2 + hashes;
                    } else {
                        i += 1;
                    }
                }
                '"' => {
                    self.in_str = true;
                    i += 1;
                }
                '\'' => {
                    // A char literal ('{', '\n', '\'') or a lifetime ('a).
                    if b.get(i + 1) == Some(&'\\') && b.get(i + 3) == Some(&'\'') {
                        i += 4;
                    } else if b.get(i + 2) == Some(&'\'') {
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
                '{' => {
                    open += 1;
                    i += 1;
                }
                '}' => {
                    close += 1;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        (open, close)
    }
}

/// The file's lines with every `#[cfg(test)]` item blanked (line numbers are
/// kept). An item ends at the `}` that closes its first `{`, or at a `;`
/// reached before any `{` (a gated `use`).
fn production_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lex = Lex::default();
    let mut gated = false; // saw #[cfg(test)], item not finished
    let mut depth = 0i32;
    let mut opened = false;
    for line in text.lines() {
        if !gated && line.trim_start().starts_with("#[cfg(test)]") {
            gated = true;
            depth = 0;
            opened = false;
            out.push(String::new());
            continue;
        }
        if gated {
            let (o, c) = lex.braces(line);
            depth += o - c;
            opened |= o > 0;
            if (opened && depth <= 0) || (!opened && line.trim_end().ends_with(';')) {
                gated = false;
            }
            out.push(String::new());
            continue;
        }
        // Keep the lexer state honest across production lines too (a raw
        // string that spans lines must not be mistaken for code).
        lex.braces(line);
        out.push(line.to_string());
    }
    out
}

/// Every offending line in `crates/*/src`, as "file:line: text".
fn violations(crates_dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    for c in std::fs::read_dir(crates_dir)
        .unwrap()
        .filter_map(Result::ok)
    {
        let src = c.path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    files.sort();
    let mut bad = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let name = f.to_string_lossy().replace('\\', "/");
        for (i, line) in production_lines(&text).iter().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if !FORBIDDEN.iter().any(|p| line.contains(p)) {
                continue;
            }
            let allowed = ALLOWED
                .iter()
                .any(|(suffix, frag, _)| name.ends_with(suffix) && line.contains(frag));
            if !allowed {
                bad.push(format!("{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    bad
}

fn workspace_crates() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

// rivet: verifies REQ-MIRROR-002
#[test]
fn no_realm_fetch_site_builds_its_source_from_the_primary_alone() {
    let bad = violations(&workspace_crates());
    assert!(
        bad.is_empty(),
        "these sites build a source from `realm.registry` or by hand, so a down primary \
         fails a realm that declares mirrors. Build the source with \
         `varve_core::mirror::Mirrors::for_realm` (realm.sources), or add the site to \
         ALLOWED with the reason it is not a realm fetch:\n{}",
        bad.join("\n")
    );
}

fn scan(src: &str) -> Vec<String> {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("demo/src");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("lib.rs"), src).unwrap();
    violations(tmp.path())
}

/// The scan must be able to fail, and must see production code that follows an
/// EARLY test module (compose.rs has one) — the old first-`#[cfg(test)]` cut
/// stopped there and left the rest unscanned.
// rivet: verifies REQ-MIRROR-002
#[test]
fn the_scan_reports_violations_after_an_early_test_module_and_skips_test_code() {
    let bad = scan(
        "fn f(realm: &R) { let s = RegistrySource::parse(&realm.registry); }\n\
         // realm.registry in a comment is not a fetch\n\
         #[cfg(test)]\nmod t {\n    fn g(realm: &R) { let _ = realm.registry; }\n    \
         fn h() { let s = \"}\"; let c = '}'; let r = r#\"}\"#; let _ = realm.registry; }\n}\n\
         fn after() { let _ = DirSource::at(p); }\n",
    );
    assert_eq!(bad.len(), 2, "{bad:?}");
    assert!(bad[0].contains("lib.rs:1:"), "{bad:?}");
    assert!(
        bad[1].contains("lib.rs:8:") && bad[1].contains("DirSource"),
        "{bad:?}"
    );
}

// rivet: verifies REQ-MIRROR-002
#[test]
fn the_scan_recognises_each_way_of_deciding_on_the_primary_alone() {
    for shape in [
        "let a = realm.registry.clone();",
        "let a = m.realm.registry;",
        "let a = ctx.realm.registry;",
        "let a = r.registry;",
        "let a = realm.sources[0].clone();",
        "let a = realm.sources.first();",
        "let a = RegistrySource::new(r);",
        "let a = OciLayoutSource::at(p);",
        "let a = DirSource::at(p);",
    ] {
        let bad = scan(&format!("fn f() {{ {shape} }}\n"));
        assert_eq!(bad.len(), 1, "{shape} must be refused: {bad:?}");
    }
    assert!(scan("fn f() { let a = realm.sources.clone(); }\n").is_empty());
}

// rivet: verifies REQ-MIRROR-002
#[test]
fn a_gated_use_and_a_gated_fn_are_blanked_too() {
    let bad = scan(
        "#[cfg(test)]\nuse x::DirSource;\n#[cfg(test)]\nfn t() { let _ = DirSource::at(p); }\n\
         fn real() {}\n",
    );
    assert!(bad.is_empty(), "{bad:?}");
}

#[test]
fn every_allowlist_entry_states_a_reason_and_still_matches_a_line_of_production_code() {
    let crates = workspace_crates();
    let mut files = Vec::new();
    for c in std::fs::read_dir(&crates).unwrap().filter_map(Result::ok) {
        let src = c.path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    for (suffix, frag, why) in ALLOWED {
        assert!(why.len() > 20, "{suffix}: an allowance needs a real reason");
        let matched = files.iter().any(|f| {
            f.to_string_lossy().ends_with(suffix)
                && std::fs::read_to_string(f).is_ok_and(|t| {
                    production_lines(&t)
                        .iter()
                        .any(|l| l.contains(frag) && FORBIDDEN.iter().any(|p| l.contains(p)))
                })
        });
        assert!(
            matched,
            "stale allowlist entry ({suffix}, {frag}): it allows no forbidden line; remove it"
        );
    }
}
