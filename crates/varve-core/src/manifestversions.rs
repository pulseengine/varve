//! The workspace version and the internal dependency pin must agree.
//!
//! `varve` depends on `varve-core` by path AND by version:
//!
//! ```toml
//! varve-core = { path = "crates/varve-core", version = "0.34.3" }
//! ```
//!
//! `cargo package` embeds that version requirement in the published crate, so
//! a stale pin means the crate on crates.io asks for a `varve-core` that is not
//! the one it was built and tested against.
//!
//! A release bumps the workspace `version` and it is easy to leave the pin
//! behind — `cargo update -w` does not touch it, because it is a requirement,
//! not a lock entry. That happened twice in a row: v0.34.1 and v0.34.2 both
//! shipped GitHub releases and both FAILED to publish to crates.io, leaving the
//! registry stranded at 0.34.0 while the tags said otherwise.
//!
//! The invariant was already checked — in `publish-crates.yml`, which runs only
//! on a tag. A tag is the point of no return: by the time that gate spoke, the
//! version was cut, the binaries were published, and the only remedy was
//! another release. The check is the same; what was wrong was WHERE it ran.
//!
//! So it runs here, with `cargo test`, on every pull request and every local
//! run — before a version can be tagged rather than after. The workflow keeps
//! its own copy for the tag-vs-workspace half, which no unit test can see.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crates/varve-core is two levels below the repo root")
            .to_path_buf()
    }

    /// Read `version = "X"` out of a line.
    fn quoted(line: &str) -> Option<&str> {
        let (_, rest) = line.split_once("version")?;
        let (_, rest) = rest.split_once('"')?;
        let (v, _) = rest.split_once('"')?;
        Some(v)
    }

    /// v0.34.1 and v0.34.2 both failed to reach crates.io this way, and both
    /// found out only after they were tagged.
    // rivet: verifies REQ-PRODUCER-002
    #[test]
    fn the_workspace_version_and_the_internal_dependency_pin_agree() {
        let manifest = std::fs::read_to_string(repo_root().join("Cargo.toml"))
            .expect("the workspace manifest is readable");

        let workspace = manifest
            .lines()
            .find(|l| l.trim_start().starts_with("version"))
            .and_then(quoted)
            .expect("the workspace declares a version");

        let dep_line = manifest
            .lines()
            .find(|l| l.contains("varve-core") && l.contains("path"))
            .expect("varve depends on varve-core by path");
        let pinned = quoted(dep_line).expect("the path dependency also pins a version");

        assert_eq!(
            pinned, workspace,
            "varve pins varve-core {pinned} but the workspace is {workspace}. \
             `cargo package` embeds this requirement, so the published crate \
             would ask for a varve-core it was never built against — and \
             `cargo publish` refuses, AFTER the tag exists. Bump both."
        );
    }
}
