//! REQ-SERVELAYER-001 (varve#286): `--layer` was declared, documented, and
//! never read, so `varve-serve --layer X` served the PIN's documentation.

#[path = "support/fixture.rs"]
mod fixture;
use fixture::*;

const BIN: &str = env!("CARGO_BIN_EXE_varve-serve");

fn two_layers() -> Fx {
    let fx = install_layer(vec![docs_tool(
        "pinned-api",
        None,
        &[("index.html", &page("pinned"))],
    )]);
    fx.install_another(
        "2026.10.2",
        2,
        vec![docs_tool(
            "other-api",
            None,
            &[("index.html", &page("other"))],
        )],
    );
    fx
}

/// With `--layer X` different from the pin, X's documentation is what is read.
// rivet: verifies REQ-SERVELAYER-001
#[test]
fn layer_selects_another_installed_layers_docs() {
    let fx = two_layers();
    let pinned = fx.run(BIN, &["--check"]);
    assert!(
        pinned.status.success(),
        "{}",
        String::from_utf8_lossy(&pinned.stderr)
    );
    assert!(String::from_utf8_lossy(&pinned.stdout).contains("pinned-api API"));

    let other = fx.run(BIN, &["--check", "--layer", "2026.10.2"]);
    assert!(
        other.status.success(),
        "{}",
        String::from_utf8_lossy(&other.stderr)
    );
    let out = String::from_utf8_lossy(&other.stdout);
    assert!(out.contains("other-api API"), "--layer was ignored: {out}");
    assert!(!out.contains("pinned-api"), "{out}");
}

/// An uninstalled `--layer` exits non-zero and names the layer.
// rivet: verifies REQ-SERVELAYER-001
#[test]
fn an_uninstalled_layer_is_refused_by_name() {
    let fx = two_layers();
    let o = fx.run(BIN, &["--check", "--layer", "2026.10.9"]);
    assert!(
        !o.status.success(),
        "an unknown layer must not fall back to the pin"
    );
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("2026.10.9"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.stdout.is_empty());
}

/// `context` and `ask` read the layer `--layer` names, too.
// rivet: verifies REQ-SERVELAYER-001
#[test]
fn layer_applies_to_context_and_ask() {
    let fx = two_layers();
    let o = fx.run(BIN, &["--layer", "2026.10.2", "context"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let md = String::from_utf8_lossy(&o.stdout);
    assert!(md.contains("layer 2026.10.2"), "{md}");
    let a = fx.run(BIN, &["--layer", "2026.10.2", "ask", "other"]);
    assert!(
        String::from_utf8_lossy(&a.stdout).contains("other-api"),
        "{}",
        String::from_utf8_lossy(&a.stdout)
    );
}

/// The words of a printed command, split the way `sh` would: single quotes
/// group, nothing else is special in what varve prints.
fn sh_words(cmd: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let (mut in_word, mut quoted) = (false, false);
    for c in cmd.chars() {
        match (c, quoted) {
            ('\'', _) => {
                quoted = !quoted;
                in_word = true;
            }
            (c, false) if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (c, _) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// varve#286 one level down: the `read` command `ask` prints for a page of
/// ANOTHER layer, run exactly as printed, reads that layer's page.
// rivet: verifies REQ-SERVELAYER-001
#[test]
fn a_printed_read_command_reads_the_layer_it_was_asked_about() {
    let fx = two_layers();
    let a = fx.run(
        BIN,
        &["--layer", "2026.10.2", "ask", "--format", "json", "other"],
    );
    assert!(a.status.success(), "{}", String::from_utf8_lossy(&a.stderr));
    let v: serde_json::Value = serde_json::from_slice(&a.stdout).unwrap();
    let hit = v["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == "docs:other-api:index.html")
        .unwrap_or_else(|| panic!("no page hit: {v}"));
    let read = hit["read"].as_str().unwrap();
    let words = sh_words(read);
    assert_eq!(words[0], "varve-serve", "{read}");
    assert!(
        words.windows(2).any(|w| w == ["--layer", "2026.10.2"]),
        "the printed command drops --layer: {read}"
    );
    let args: Vec<&str> = words[1..].iter().map(String::as_str).collect();
    let o = fx.run(BIN, &args);
    assert!(
        o.status.success(),
        "`{read}` failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stdout).contains("other"));
    // And without an override nothing is added.
    let plain = fx.run(BIN, &["ask", "--format", "json", "pinned"]);
    let v: serde_json::Value = serde_json::from_slice(&plain.stdout).unwrap();
    assert!(!v.to_string().contains("--layer"), "{v}");
}

/// `--layer` is global: before or after the subcommand, the same answer.
// rivet: verifies REQ-SERVELAYER-001
#[test]
fn layer_is_accepted_before_or_after_the_subcommand() {
    let fx = two_layers();
    let before = fx.run(BIN, &["--layer", "2026.10.2", "context"]);
    let after = fx.run(BIN, &["context", "--layer", "2026.10.2"]);
    assert!(
        after.status.success(),
        "{}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert_eq!(before.stdout, after.stdout);
    let b = fx.run(BIN, &["--layer", "2026.10.2", "ask", "other"]);
    let a = fx.run(BIN, &["ask", "other", "--layer", "2026.10.2"]);
    assert!(a.status.success(), "{}", String::from_utf8_lossy(&a.stderr));
    assert_eq!(a.stdout, b.stdout);
    let p = fx.run(
        BIN,
        &[
            "page",
            "--layer",
            "2026.10.2",
            "--",
            "other-api",
            "index.html",
        ],
    );
    assert!(p.status.success(), "{}", String::from_utf8_lossy(&p.stderr));
}

/// The reviewer's three hostile examples, through a real deposit and install:
/// what `context` and `ask` print is quoted, so running it executes nothing.
// rivet: verifies REQ-AGENTDOCS-001
#[test]
fn hostile_layer_names_print_as_quoted_words() {
    use varve_core::PayloadKind;
    let fx = install_layer(vec![
        held_tool("a:b;touch PWNED", "1.0.0", PayloadKind::Wit),
        docs_tool(
            "api",
            Some("t$(touch PWNED)"),
            &[("index.html", &page("hostile"))],
        ),
        script_tool(
            "t$(touch PWNED)",
            "1.0.0",
            "echo 'About\n\nCommands:\n  go  Go'",
        ),
    ]);
    let o = fx.run(BIN, &["context"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let md = String::from_utf8_lossy(&o.stdout);
    assert!(
        md.contains("--package='a:b;touch PWNED@1.0.0'"),
        "wit command is not quoted: {md}"
    );
    assert!(
        md.contains("--for='t$(touch PWNED)'"),
        "--for is not quoted: {md}"
    );
    let a = fx.run(BIN, &["ask", "--format", "json", "t touch PWNED go"]);
    let out = String::from_utf8_lossy(&a.stdout);
    assert!(
        out.contains("'t$(touch PWNED)' go --help") || out.contains("'t$(touch PWNED)' --help"),
        "tool command is not quoted: {out}"
    );
    assert!(!out.contains("\"t$(touch PWNED) "), "{out}");
}
