//! An SDK exported to a SHORTER path than it was built under still runs
//! (REQ-SDK-001), measured on a real Yocto SDK rather than a fixture.
//!
//! Reported against varve 0.39: zephyr-sdk 1.0.1 exported to a shorter path
//! accepted the export and then could not start its tools — `dtc`: "cannot
//! read file data: Error 21". varve shortened the loader's SYSDIRS paths in
//! place but left `.sysdirslen`, so ld.so stepped through the table by the old
//! lengths and opened a file with an empty name. A synthetic ELF can prove the
//! bytes; only RUNNING a relocated tool proves the loader.
//!
//! Opt-in, because it needs the Zephyr SDK host-tools installer and an x86_64
//! Linux host: set `VARVE_SDK_SHAR` to `zephyr-sdk-x86_64-hosttools-*.sh` and
//! run with `--ignored`. CI does both (the `sdk relocation runs` job).

use std::path::Path;
use std::process::Command;

const BUILT: &str = "/usr/local/oe-sdk-hardcoded-buildpath";

/// The installer is a shell script with the SDK appended after a `MARKER:`
/// line, as an xz-compressed tar — the archive `export-sdk` consumes.
fn payload(shar: &[u8]) -> Vec<u8> {
    let marker = b"\nMARKER:\n";
    let at = shar
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("a Yocto SDK installer carries its payload after MARKER:");
    shar[at + marker.len()..].to_vec()
}

fn export_and_run(dest: &Path) -> std::process::Output {
    let shar = std::fs::read(std::env::var("VARVE_SDK_SHAR").expect("VARVE_SDK_SHAR"))
        .expect("read the installer");
    let _ = std::fs::remove_dir_all(dest);
    let report = varve_core::export_sdk(&payload(&shar), BUILT, dest).expect("export");
    assert!(report.patched_fields > 0, "{report:?}");
    Command::new(dest.join("sysroots/x86_64-pokysdk-linux/usr/bin/dtc"))
        .arg("--version")
        .output()
        .expect("spawn dtc")
}

// rivet: verifies REQ-SDK-001
#[test]
#[ignore = "needs VARVE_SDK_SHAR and an x86_64 Linux host"]
fn a_tool_runs_after_export_to_a_shorter_path() {
    // 13 characters against a 37-character build prefix.
    let out = export_and_run(Path::new("/tmp/sdk-short"));
    assert!(
        out.status.success(),
        "dtc did not start from the relocated sdk: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Version: DTC"),
        "{out:?}"
    );
}

// rivet: verifies REQ-SDK-001
#[test]
#[ignore = "needs VARVE_SDK_SHAR and an x86_64 Linux host"]
fn a_tool_runs_after_export_to_a_path_of_equal_length() {
    // Exactly as long as the build prefix: the one case the report found working.
    let dest = format!("/tmp/{}", "e".repeat(BUILT.len() - "/tmp/".len()));
    assert_eq!(dest.len(), BUILT.len());
    let out = export_and_run(Path::new(&dest));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
