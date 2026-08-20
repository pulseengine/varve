//! Producer-side safety: the two ways CI can sign something that quietly
//! destroys or quietly does nothing.
//!
//! * REQ-NODESTROY-001 — `deposit --out DIR` rewrites the whole layout,
//!   including `index.json`. Into a directory that already carries referrers
//!   (a baseline line-status, a signed line-index, attestations) that dropped
//!   every one of them and reported success. Three docs topics warn about it
//!   and zero lines of code guarded it.
//! * REQ-ADVISORY-002 — one wrong character in an advisory's `affected` layer
//!   id signs cleanly and the advisory then fires for nobody.
//!
//! These are exercised through the library seams the CLI calls, at the level
//! where a whole producer pipeline actually runs: deposit, attach a status,
//! attach an index, attach an attestation — then do the wrong thing.

use std::path::Path;

use varve_core::attest::{AttestationKind, sign as sign_statement, statement};

/// Every file under `root`, relative path -> bytes, deterministically ordered.
/// The refusal contract is BYTE-IDENTICAL, not "roughly unchanged": a partial
/// write is worse than either outcome, so the test compares content, not a
/// file count.
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

const LINE: &str = "2026.08";
const LAYER: &str = "2026.08.0";

fn deposit_spec(layer: &str, counter: u64) -> varve_core::DepositSpec {
    varve_core::DepositSpec {
        includes: Vec::new(),
        layer: layer.parse().unwrap(),
        channel: "qualified".into(),
        counter,
        issued_at: "2026-08-07T00:00:00Z".into(),
        tools: vec![varve_core::DepositTool {
            name: "synth".into(),
            version: "0.45.0".into(),
            platform: None,
            bytes: b"synth-bytes".to_vec(),
            source: None,
            runner: None,
            kind: None,
            sdk_prefix: None,
        }],
    }
}

fn status_doc(counter: u64, affected: &[&str]) -> varve_core::LineStatus {
    varve_core::LineStatus {
        line: LINE.into(),
        counter,
        issued_at: "2026-08-07T00:00:00Z".into(),
        support_until: None,
        yanked: Default::default(),
        known_problems: vec![varve_core::KnownProblem {
            id: "VARVE-2026-0001".into(),
            title: "miscompilation under -O2".into(),
            severity: "high".into(),
            affected: affected.iter().map(|s| s.to_string()).collect(),
            workaround: Some("build with -O1".into()),
            detection: None,
            mitigation: None,
        }],
    }
}

fn index_doc(counter: u64, layers: &[(&str, &str, u64)]) -> varve_core::LineIndex {
    varve_core::LineIndex {
        line: LINE.into(),
        counter,
        issued_at: "2026-08-07T00:00:00Z".into(),
        layers: layers
            .iter()
            .map(|(layer, digest, counter)| varve_core::IndexedLayer {
                layer: (*layer).into(),
                digest: (*digest).into(),
                channel: "qualified".into(),
                counter: *counter,
            })
            .collect(),
    }
}

/// A layout carrying everything the producer pipeline attaches after deposit:
/// the baseline line-status, the realm's signed line index, and one
/// attestation. Returns (layout dir, the deposited manifest digest).
fn full_pipeline(tmp: &Path, sk: &[u8]) -> (std::path::PathBuf, String) {
    let layout = tmp.join("layout");
    let outcome = varve_core::deposit(&deposit_spec(LAYER, 1), sk, "root-1", &layout).unwrap();

    let status = status_doc(1, &[LAYER]).sign(sk, "root-1").unwrap();
    varve_core::attach_status_envelope_to_layout(&layout, status.as_bytes()).unwrap();

    let index = index_doc(1, &[(LAYER, &outcome.digest, 1)])
        .sign(sk, "root-1")
        .unwrap();
    varve_core::attach_index_envelope_to_layout(&layout, index.as_bytes()).unwrap();

    let sbom = br#"{"bomFormat":"CycloneDX"}"#;
    let st = statement(
        LAYER,
        &outcome.digest,
        AttestationKind::Sbom,
        sbom,
        "acme-ci",
    );
    let envelope = sign_statement(&st, sk, "root-1").unwrap();
    varve_core::attestcarry::attach(&layout, envelope.as_bytes(), sbom).unwrap();

    (layout, outcome.digest)
}

// rivet: verifies REQ-NODESTROY-001
#[test]
fn re_depositing_over_attached_evidence_is_refused_and_leaves_the_layout_byte_identical() {
    // The own-realm operator hit this BY ACCIDENT: a second `deposit --out` at
    // the same directory returned exit 0 with a message byte-identical to a
    // clean run, and the baseline status, the signed index and every
    // attestation were gone. For a realm declaring `signed-index = true` every
    // consumer install after that fails closed — the tool's own success
    // message is the last thing anyone sees before the outage.
    let tmp = tempfile::tempdir().unwrap();
    let (sk, _pk) = varve_core::generate_root_keypair();
    let (layout, _digest) = full_pipeline(tmp.path(), &sk);

    let before = snapshot(&layout);
    let err = varve_core::deposit(&deposit_spec(LAYER, 2), &sk, "root-1", &layout)
        .expect_err("a deposit that would destroy signed work must be refused");
    let msg = err.to_string();

    // Name what was found. "Refused" without the inventory leaves the operator
    // guessing which artifact they nearly lost.
    assert!(
        msg.contains("line-status"),
        "the refusal must name the baseline status it found: {msg}"
    );
    assert!(
        msg.contains("line-index"),
        "the refusal must name the signed index it found: {msg}"
    );
    assert!(
        msg.contains("attestation"),
        "the refusal must name the attestations it found: {msg}"
    );

    // Recover from the MESSAGE, not from the docs. Three separate docs topics
    // warned about this and it still happened; the fix belongs where the
    // operator is standing.
    assert!(
        msg.contains("varve attach-status") && msg.contains("varve attach-index"),
        "the refusal must carry the re-attach sequence: {msg}"
    );
    assert!(
        msg.contains("--force"),
        "the refusal must say how to override it deliberately: {msg}"
    );

    // A partial write is worse than either outcome.
    assert_eq!(
        before,
        snapshot(&layout),
        "a refused deposit must leave the layout byte-identical"
    );
}

// rivet: verifies REQ-NODESTROY-001
#[test]
fn force_is_the_deliberate_way_through_and_it_really_does_drop_the_evidence() {
    // Re-depositing on purpose is a real workflow, so the guard has to have a
    // door. It also has to be the destructive thing it says it is — a --force
    // that quietly preserved the referrers would be a different command
    // wearing this one's name.
    let tmp = tempfile::tempdir().unwrap();
    let (sk, _pk) = varve_core::generate_root_keypair();
    let (layout, _digest) = full_pipeline(tmp.path(), &sk);
    assert!(!varve_core::scan_layout_referrers(&layout).is_empty());

    varve_core::deposit_with_options(
        &deposit_spec(LAYER, 2),
        &sk,
        "root-1",
        &layout,
        &varve_core::DepositOptions { force: true },
    )
    .expect("--force overrides the guard");

    assert!(
        varve_core::scan_layout_referrers(&layout).is_empty(),
        "--force is destructive by design — the referrers are gone, and the operator \
         asked for that"
    );
}

// rivet: verifies REQ-ADVISORY-002
#[test]
fn attaching_before_the_index_exists_reports_the_check_it_could_not_run() {
    // The documented CI order attaches the status BEFORE the index, so the
    // ordinary case is that no listing is in reach. Silence there would be the
    // defect one level up: a "signed" that implies a completeness nobody
    // established. The answer has to name the check that did NOT run.
    let tmp = tempfile::tempdir().unwrap();
    let (sk, _pk) = varve_core::generate_root_keypair();
    let layout = tmp.path().join("layout");
    varve_core::deposit(&deposit_spec(LAYER, 1), &sk, "root-1", &layout).unwrap();

    let status = status_doc(1, &[LAYER]).sign(&sk, "root-1").unwrap();
    let (_line, counter, check) =
        varve_core::attach_status_envelope_to_layout_checked(&layout, status.as_bytes(), false)
            .unwrap();
    assert_eq!(counter, 1);
    assert!(
        !check.existence_checked,
        "a layout holds ONE layer — it is not a listing of the line"
    );
    assert!(
        check.note.contains("NOT") && check.note.contains("line-index"),
        "the note must name the check that did not run, and how to get it: {}",
        check.note
    );
}

// rivet: verifies REQ-ADVISORY-002
#[test]
fn signing_against_the_realms_index_refuses_the_typo_before_a_signature_exists() {
    // The `sign-status` seam, one step earlier than attach: given the line's
    // signed index the check can run at SIGN time, which is the cheapest
    // possible place — the point of the requirement is that the signature must
    // not come into existence.
    let (sk, _pk) = varve_core::generate_root_keypair();
    let index = index_doc(1, &[(LAYER, "sha256:aa", 1)])
        .sign(&sk, "root-1")
        .unwrap();
    // Verified against the root that is about to sign: an unverified listing
    // is one an attacker could choose, and one naming the typo would wave the
    // dead advisory through.
    let known = varve_core::known_layers_from_index(index.as_bytes(), &sk[32..]).unwrap();

    let err = status_doc(2, &["2026.08.10"])
        .sign_against(&known, false, &sk, "root-1")
        .expect_err("an advisory that can never fire must not be signed at all");
    assert!(err.to_string().contains("2026.08.10"), "{err}");

    // …and --force is the door for pre-signing a layer not deposited yet,
    // which must not be silent about the check it skipped.
    let (_envelope, check) = status_doc(2, &["2026.08.10"])
        .sign_against(&known, true, &sk, "root-1")
        .expect("--force pre-signs");
    assert!(!check.existence_checked);
    assert!(check.note.contains("--force"), "{}", check.note);
}

// rivet: verifies REQ-ADVISORY-002
#[test]
fn an_advisory_naming_a_layer_the_line_does_not_have_is_refused_where_the_line_is_visible() {
    // One wrong character. `2026.08.10` parses, belongs to the line, and is not
    // a layer that exists — so the advisory attaches, the producer sees
    // success, the consumer sees nothing, and the yank silently does not
    // exist. The layout carries the realm's SIGNED index, so the set of layers
    // this line has is right there to check against.
    let tmp = tempfile::tempdir().unwrap();
    let (sk, _pk) = varve_core::generate_root_keypair();
    let (layout, _digest) = full_pipeline(tmp.path(), &sk);

    let typo = status_doc(2, &["2026.08.10"]).sign(&sk, "root-1").unwrap();
    let err = varve_core::attach_status_envelope_to_layout(&layout, typo.as_bytes())
        .expect_err("an advisory that can never fire must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("2026.08.10"),
        "the refusal must name the id that would never fire: {msg}"
    );
    assert!(
        msg.contains(LAYER),
        "the refusal must list the ids that DO exist — varve already does this \
         shape for tools ('it exposes: …'): {msg}"
    );
}
