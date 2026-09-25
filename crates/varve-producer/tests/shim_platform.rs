//! What `shim install` may write, and what the docs may claim (DD-031).

fn read(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// A shim that can only be a COPY is refused, not written (DD-031).
///
/// The failure being prevented is silent: a copy binds to the varve that
/// existed when `shim install` ran, `self-update` replaces the binary without
/// touching shims, and every shim keeps running the old verification and
/// refusal logic forever. The pin still resolves the right LAYER, so the tool
/// dispatched is correct — what goes stale is varve's own judgement about
/// whether to accept bytes, which is the worst part to have quietly out of
/// date.
///
/// This is a SOURCE-level check because the branch cannot run here: no
/// Windows build exists (varve#197), so nothing on unix would notice the
/// refusal being replaced by a `fs::copy` again. It was type-checked once by
/// compiling it under `cfg(all())`; this keeps it honest afterwards.
// rivet: verifies REQ-BOOTSTRAP-001
#[test]
fn a_shim_that_could_only_be_a_copy_is_refused() {
    let src = read("crates/varve/src/main.rs");
    let branch = src
        .split("#[cfg(not(unix))]")
        .nth(1)
        .expect("shim install no longer has a non-unix branch at all");
    let head = &branch[..branch.len().min(1200)];
    assert!(
        head.contains("bail!"),
        "the non-unix shim branch does not refuse. If it writes a copy again, \
         `self-update` leaves every shim stale and nothing reports it (DD-031)"
    );
    assert!(
        !head.contains("fs::copy"),
        "the non-unix shim branch copies varve — the exact staleness DD-031 refuses"
    );
    // The refusal has to send the reader somewhere that still works.
    assert!(
        head.contains("varve run"),
        "the refusal does not name the alternative that is never stale (`varve run`)"
    );
}

/// The documentation must not describe behaviour the binary does not have.
// rivet: verifies REQ-BOOTSTRAP-001
#[test]
fn the_shim_docs_do_not_promise_a_windows_copy() {
    let doc = read("crates/varve/docs/cmd-shim.md");
    let lower = doc.to_lowercase();
    assert!(
        !lower.contains("on windows a copy") && !lower.contains("on windows, a copy"),
        "cmd-shim.md still tells a Windows reader that varve writes a copy there. No build \
         has ever produced that behaviour, and `shim install` now refuses instead"
    );
    assert!(
        lower.contains("refuses") || lower.contains("refuse"),
        "cmd-shim.md does not say that shim install refuses where only a copy is possible"
    );
}
