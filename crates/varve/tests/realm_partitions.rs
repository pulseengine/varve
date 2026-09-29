//! `effective_root` may only ever be handed a BASE root.
//!
//! `Realm::effective_root` maps a base root to `<base>/realms/<fingerprint>`.
//! Hand it a path that is already a partition and it appends a second
//! `realms/<fingerprint>`, nesting one realm inside another.
//!
//! That is not a hypothetical. On the first real two-realm composition,
//! `fetch_included_layer` derived an included realm's partition from the
//! COMPOSING realm's root instead of the base root. `varve install` printed
//! "fetched composed layer … from realm 'pulseengine'" and exited 0; the very
//! next command reported the layer was not installed, because the composition
//! walk looks for siblings. A success that leaves nothing usable behind is the
//! worst shape this codebase produces, and the published workaround for
//! v0.38.0 — "promote them once before verifying" — is what it cost consumers.
//!
//! The fix is one correct variable at one call site, which is exactly the kind
//! of thing that comes back. Reverting it to `ctx.store.root()` keeps the
//! whole suite green: verified by reintroducing it, 108 passed, 0 failed.
//! Nothing else here can see the difference, because reaching that line needs
//! a live OCI registry for a second realm.
//!
//! So this gate reads the source instead, and enforces the rule rather than
//! the instance: every `effective_root` argument in shipped code must NAME a
//! base root. A new call site spelled any other way fails this test — which is
//! the point, since a new call site is precisely where this returns.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.rs` file under `crates/*/src`, with its repo-relative path.
fn shipped_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let crates = repo_root().join("crates");
    let mut stack: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("crates/ is unreadable")
        .filter_map(|e| e.ok())
        .map(|e| e.path().join("src"))
        .filter(|p| p.is_dir())
        .collect();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("a src/ directory is unreadable") {
            let path = entry.expect("unreadable directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(repo_root())
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"));
                out.push((rel, text));
            }
        }
    }
    assert!(!out.is_empty(), "found no shipped sources to scan at all");
    out
}

/// The argument text of each `effective_root(...)` call, by file.
///
/// Split on the call rather than stepping a cursor by hand: the arguments here
/// contain no nested parentheses beyond a single `root()`, so the argument is
/// everything up to the matching close, found by counting depth from the open.
fn effective_root_args(src: &str) -> Vec<String> {
    let mut args = Vec::new();
    for tail in src.split("effective_root(").skip(1) {
        let mut depth = 1usize;
        let mut arg = String::new();
        for ch in tail.chars() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            arg.push(ch);
        }
        // The loop breaks the moment depth returns to 0, so 0 is the balanced
        // case and anything left over means the call never closed.
        assert_eq!(depth, 0, "unbalanced effective_root( call: {arg}");
        args.push(arg.trim().to_string());
    }
    args
}

/// Shipped code hands `effective_root` a base root, and says so in the name.
///
/// The rule is deliberately about the NAME. A reviewer cannot tell from
/// `store.root()` whether that store is the base or a partition — that is the
/// ambiguity the original bug lived in — but `base`, `base_root` and
/// `ctx.base_root` all state which one they are, and are wrong out loud if
/// they ever stop being true.
// rivet: verifies REQ-COMPOSEINSTALL-001
#[test]
fn effective_root_is_only_ever_given_a_base_root() {
    let mut seen = 0usize;
    for (file, src) in shipped_sources() {
        // The definition and its own doc examples live with the function.
        if file.ends_with("varve-core/src/realm.rs") {
            continue;
        }
        for arg in effective_root_args(&src) {
            seen += 1;
            assert!(
                arg.contains("base"),
                "{file}: `effective_root({arg})` is not named as a base root.\n\
                 `effective_root` maps a BASE root to `<base>/realms/<fp>`; give it a \
                 path that is already a partition and realms nest inside each other, \
                 install still exits 0, and the layer is unreachable afterwards.\n\
                 If this argument really is the base root, name it so (`base`, \
                 `base_root`) — the name is the only thing a reviewer can check here."
            );
        }
    }
    assert!(
        seen >= 3,
        "expected to scan at least the three known call sites, saw {seen} — \
         the scan stopped finding them, so this gate is no longer checking anything"
    );
}

/// The composing realm's own store is never what an include is fetched into.
///
/// Narrower and blunter than the rule above, aimed at the exact line that
/// broke. Kept separate so that if someone legitimately introduces a new
/// base-named call site, this one still pins the regression itself.
// rivet: verifies REQ-COMPOSEINSTALL-001
#[test]
fn an_included_realm_is_not_fetched_into_the_composing_realms_partition() {
    let src = std::fs::read_to_string(repo_root().join("crates/varve/src/main.rs"))
        .expect("cannot read the varve binary's source");
    let body = src
        .split("fn fetch_included_layer(")
        .nth(1)
        .expect("fetch_included_layer is gone — this gate needs re-aiming");
    let body = &body[..body.len().min(2000)];
    assert!(
        body.contains("effective_root(&ctx.base_root)"),
        "fetch_included_layer no longer derives the included realm's partition from \
         the base root. Deriving it from the composing realm's root nests the two, \
         and install reports success either way."
    );
    assert!(
        !body.contains("effective_root(ctx.store.root())"),
        "fetch_included_layer is back to `effective_root(ctx.store.root())` — \
         `ctx.store` is ALREADY a partition, so this nests the included realm \
         inside the composing one and the layer is unreachable after install"
    );
}
