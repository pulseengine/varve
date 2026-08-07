//! The platform dimension (REQ-PLATFORM-001, DD-001).
//!
//! A layer is one manifest for N platforms — the OCI index's own mechanism,
//! not a substitution language. Deposit stamps every entry with a target
//! triple; install selects only entries for the host (or an explicit
//! override). Entries WITHOUT a platform annotation are platform-independent
//! — layers deposited before this dimension existed keep working, and a
//! depositor that makes no platform claim gets no platform filtering.
//! A fully-stamped layer with nothing for the host fails closed: a
//! wrong-architecture binary never reaches the core.

/// Annotation carrying an entry's target triple.
pub const ANN_PLATFORM: &str = "eu.pulseengine.platform";

/// The host's target triple, in the same vocabulary deposits use.
pub fn host_platform() -> String {
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "macos" => format!("{arch}-apple-darwin"),
        "linux" => format!("{arch}-unknown-linux-gnu"),
        "windows" => format!("{arch}-pc-windows-msvc"),
        other => format!("{arch}-{other}"),
    }
}

/// Does an entry's (optional) platform annotation admit this platform?
pub fn entry_matches(entry_platform: Option<&str>, platform: &str) -> bool {
    match entry_platform {
        None => true,
        Some(p) => p == platform,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rivet: verifies REQ-PLATFORM-001
    #[test]
    fn unstamped_entries_are_platform_independent_and_stamped_ones_are_exact() {
        assert!(entry_matches(None, "aarch64-apple-darwin"));
        assert!(entry_matches(
            Some("aarch64-apple-darwin"),
            "aarch64-apple-darwin"
        ));
        assert!(!entry_matches(
            Some("x86_64-unknown-linux-gnu"),
            "aarch64-apple-darwin"
        ));
    }

    // rivet: verifies REQ-PLATFORM-001
    #[test]
    fn the_host_platform_is_a_target_triple() {
        let host = host_platform();
        assert!(
            host.split('-').count() >= 2 && host.contains(std::env::consts::ARCH),
            "host platform should be triple-shaped: {host}"
        );
    }
}
