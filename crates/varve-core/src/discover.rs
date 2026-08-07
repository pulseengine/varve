//! Pin discovery — walk up from the working directory (DD-006).
//!
//! The `rust-toolchain.toml` reflex: the nearest `varve.toml` on the path from
//! the working directory to the filesystem root names the project's layer.
//! Discovery never consults the environment, never falls through to a global
//! default — a project without a pin has no layer, which at resolution time is
//! an error, not a fallback.

use std::path::{Path, PathBuf};

/// The pin file name discovered by the walk.
pub const PIN_FILE: &str = "varve.toml";

/// Walk up from `start`, returning the nearest `varve.toml`.
pub fn find_pin(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(d) = dir {
        let candidate = d.join(PIN_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // rivet: verifies REQ-PIN-001
    #[test]
    fn finds_pin_in_the_starting_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let pin = tmp.path().join("varve.toml");
        fs::write(&pin, "").unwrap();
        assert_eq!(find_pin(tmp.path()), Some(pin));
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn walks_up_to_an_ancestor_pin() {
        let tmp = tempfile::tempdir().unwrap();
        let pin = tmp.path().join("varve.toml");
        fs::write(&pin, "").unwrap();
        let deep = tmp.path().join("a/b/c");
        fs::create_dir_all(&deep).unwrap();
        assert_eq!(find_pin(&deep), Some(pin));
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn nearest_pin_wins() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("varve.toml"), "").unwrap();
        let sub = tmp.path().join("sub");
        fs::create_dir_all(&sub).unwrap();
        let near = sub.join("varve.toml");
        fs::write(&near, "").unwrap();
        assert_eq!(find_pin(&sub), Some(near));
    }

    // rivet: verifies REQ-PIN-001
    #[test]
    fn no_pin_means_none_not_a_default() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("x/y");
        fs::create_dir_all(&deep).unwrap();
        assert_eq!(find_pin(&deep), None);
    }
}
