//! REQ-IMMUTABLE-001 clauses 4 and 5, which are properties of *where* the
//! check lives rather than of what a function returns.

use std::process::Command;

fn producer() -> &'static str {
    env!("CARGO_BIN_EXE_varve-producer")
}

fn src(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Clause 5. The whole reason this check lives in the producer is that
/// `varve deposit` contacts no network — "varve runs no server and pushes
/// nothing, by design" — and buying a publisher-side fix with that property
/// would be a bad trade.
///
/// varve-core does carry an HTTP client (install must fetch). The claim is
/// narrower and this pins the narrow version: the DEPOSIT path does not use it.
// rivet: verifies REQ-IMMUTABLE-001
#[test]
fn the_deposit_path_gained_no_network_access() {
    let deposit = src("../varve-core/src/deposit.rs");
    // HTTP CLIENTS, not URLs. deposit.rs legitimately contains identity URLs
    // (a cosign signer is spelled as a https://github.com/... workflow ref), and
    // an assertion that tripped on those would be testing its own crudeness —
    // it failed exactly that way when first written.
    for client in ["ureq", "reqwest", "TcpStream", "hyper::", "std::net"] {
        assert!(
            !deposit.contains(client),
            "varve-core/src/deposit.rs now uses `{client}` — the immutability \
             check must not have been moved into the deposit path, which is \
             offline by design"
        );
    }
    // And the check really is in the producer.
    assert!(src("src/registry.rs").contains("oras"));
}

/// Clause 4. The escape hatch must exist, must not be reachable by accident,
/// and must say what it destroys.
// rivet: verifies REQ-IMMUTABLE-001
#[test]
fn replacing_a_published_layer_requires_saying_so_and_announces_it() {
    let help = Command::new(producer())
        .args(["publish-check", "--help"])
        .output()
        .expect("runs");
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("--replace-published"), "{help}");
    // Not a short flag, not a default, and the help says what it costs.
    assert!(
        help.contains("nobody has consumed") || help.contains("does not retract"),
        "the escape hatch must state its cost: {help}"
    );

    // The source of the announcement: replacing warns, loudly, on stderr.
    let main = src("src/main.rs");
    assert!(
        main.contains("::warning::REPLACING published layer"),
        "replacing must announce itself in the run that does it"
    );
}

/// The refusal is the default. A caller who passes nothing gets stopped.
// rivet: verifies REQ-IMMUTABLE-001
#[test]
fn the_default_is_to_refuse_rather_than_to_replace() {
    let main = src("src/main.rs");
    // `replace_published` gates the publish decision, and is a long flag only.
    assert!(
        main.contains(r#"#[arg(long = "replace-published")]"#),
        "{main:.0}"
    );
    assert!(
        !main.contains(r#"short = 'r'"#),
        "a single keystroke must not replace a published layer"
    );
}
