//! `varve`'s own subcommands, as `ask` knows them.
//!
//! `ask` must find `varve export-vsix` — the command that gets a held payload
//! out — but `varve` is not a pinned tool, so there is no verified binary to
//! harvest, and running whichever `varve` happens to be on PATH would break the
//! rule that only verified bytes are executed. The table is therefore static,
//! with the first sentence of each command's own `--help` text (and any
//! caveat sentence, as everywhere).
//!
//! A static table can drift, so [`tests::the_table_names_every_varve_subcommand`]
//! compares it with the subcommands declared in `crates/varve/src/main.rs`: a
//! new `varve` command fails this crate's tests until it is listed here.

/// `(subcommand, one-sentence description)`.
pub const COMMANDS: &[(&str, &str)] = &[
    (
        "archive",
        "Extract the core: export an installed layer as a directory-shaped OCI image layout — the offline artifact of record",
    ),
    (
        "attach-index",
        "(CI) Attach a signed line-index envelope to a deposit layout, so an offline consumer of a realm declaring `signed-index = true` can obtain it (REQ-INDEXAUTH-001)",
    ),
    (
        "attach-status",
        "(CI) Attach a signed line-status envelope to a deposit layout as its baseline, so `varve status` works after an offline install and the registry can carry it (REQ-STATUS-DIST-001)",
    ),
    (
        "check-attestation",
        "Check that an attestation belongs to the pinned layer: verify the statement against the trust root, then re-hash the carried bytes and confirm the layer it names is the one resolved here (REQ-ATTEST-001)",
    ),
    (
        "completions",
        "Emit shell completion scripts (zsh, bash, fish, ...)",
    ),
    (
        "deposit",
        "(CI) Assemble and SIGN a layer — the only way a layer comes into being",
    ),
    (
        "diff",
        "What changing from one installed layer to another would change (CI)",
    ),
    (
        "docs",
        "Embedded, queryable documentation (offline). `varve docs` lists topics; `varve docs <topic>` shows one; `varve docs check --coverage` asserts every subcommand is documented (REQ-DOCS-001)",
    ),
    (
        "env",
        "Print idempotent shell code putting the shim directory on PATH",
    ),
    (
        "exit-codes",
        "The exit-code contract every varve command obeys — what a pipeline gates on (REQ-CIGATE-001)",
    ),
    (
        "export-bazel",
        "Compile a Bazel checksum registry (rules_wasm_component schema) from a verified installed layer — every hash Bazel enforces becomes a transcription from the signed manifest instead of TOFU",
    ),
    (
        "export-bazel-distdir",
        "Materialise a Bazel distdir of the layer's verified `.crate` tarballs (REQ-VENDOR-002, air-gap rules_rust)",
    ),
    (
        "export-cargo",
        "Materialise a Cargo local registry from the layer's verified `crate` entries + a `.cargo/config.toml` source-replacement, so a consumer builds offline against varve-signed crates (REQ-CRATE-001)",
    ),
    (
        "export-crates-vendor",
        "Materialise a `cargo vendor`-shaped directory from the layer's verified `crate` entries — consumed offline by bare Cargo and Corrosion (REQ-VENDOR-001). rules_rust needs BUILD files on top of this tree (REQ-VENDOR-002), not yet emitted",
    ),
    (
        "export-docs",
        "Materialise the layer's verified `docs` payload — the documentation for the versions this layer pins (REQ-LAYERDOCS-001)",
    ),
    (
        "export-sdk",
        "Unpack and RELOCATE the layer's verified `sdk` tree into a directory you can source (REQ-SDK-001 clause 3)",
    ),
    (
        "export-vsix",
        "Lay the layer's verified `vsix` entries out as `publisher.name-version.vsix` files, so `code --install-extension <file>` installs an editor extension whose bytes varve signed rather than whatever the marketplace serves today (REQ-VSIX-001)",
    ),
    (
        "export-wit",
        "Export the layer's verified `wit` packages as a `wkg` local registry tree, for the package named by --package and its dependencies",
    ),
    (
        "inspect",
        "What is actually IN a layer: every payload's name, version, kind and platform, whether varve DISPATCHES it or merely HOLDS it, and every layer of the composition it came from (REQ-INSPECT-001)",
    ),
    (
        "install",
        "Resolve this project's pin, fetch, verify against the trust root, and lay the layer down in the core",
    ),
    (
        "keygen",
        "Mint a signing key and its public half — the value a realm pins as `trust-root` (REQ-KEYGEN-001)",
    ),
    (
        "layer-spec",
        "(CI) Translate a realm's `layer.toml` into the environment the layer assembler reads (REQ-LAYERREPO-001)",
    ),
    ("list", "Layers present in the local core"),
    ("outdated", "Is there a newer layer for this line? (CI)"),
    (
        "pubkey",
        "Print the public half of an existing signing key, in exactly the form a realm's `trust-root` accepts",
    ),
    (
        "run",
        "Dispatch a tool from the pinned layer, with the layer identity in the environment (VARVE_LAYER, VARVE_LAYER_MANIFEST_DIGEST) so provenance tooling can record which qualified set produced the output",
    ),
    (
        "sbom",
        "Emit an SBOM for a verified layer, transcribed from its SIGNED manifest rather than scanned from disk — every component, version and hash is copied from what the trust root anchored (REQ-SBOM-001)",
    ),
    (
        "self-update",
        "Update varve itself: check the latest release, verify it with the RUNNING binary against the trust root (old-verifies-new), replace atomically",
    ),
    (
        "self-verify",
        "Verify a varve release file against its signed SHA256SUMS envelope — the tool that gates the toolchain clearing its own gate",
    ),
    (
        "shim",
        "Shims on PATH: thin dispatchers that resolve the pin from the invocation's working directory and exec — switching projects is cd",
    ),
    (
        "sign-attestation",
        "(CI) Sign a statement binding an attestation to a layer: \"this digest, of this kind, from this producer, accompanies this layer\" (REQ-ATTEST-001). varve vouches for the ASSOCIATION and the bytes' integrity — never for what the producer claimed",
    ),
    (
        "sign-index",
        "(CI) Validate and sign a line-index document — the realm's statement of which layers a line contains (REQ-INDEXAUTH-001)",
    ),
    (
        "sign-status",
        "(CI) Validate and sign a line-status document into a DSSE envelope",
    ),
    (
        "sign-sums",
        "(CI) Sign a release SHA256SUMS.txt into the DSSE envelope `self-verify` consumes — the producing half of DD-009",
    ),
    (
        "status",
        "Support window, yank state and known problems for the pinned layer, from the newest verified line-status document",
    ),
    (
        "support-horizon",
        "(CI) The support horizon for a layer issued now, derived from the channel's stated policy (REQ-SUPPORTUNTIL-001)",
    ),
    (
        "verify",
        "Re-check the pinned layer offline: retained signature, the signed digest of every entry FOR THIS PLATFORM, each composed layer, the line's anti-rollback mark, and PATH shadowing",
    ),
    (
        "which",
        "Which binary would actually run here — and which layer it comes from",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// `Cmd`'s variants in `crates/varve/src/main.rs`, as kebab-case names.
    fn declared() -> Vec<String> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../varve/src/main.rs");
        let src = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        let body = src
            .split("enum Cmd {")
            .nth(1)
            .expect("varve's `enum Cmd` is where this test expects it")
            .split("\n}\n")
            .next()
            .unwrap();
        let mut out = Vec::new();
        for line in body.lines() {
            // A variant sits at exactly four spaces of indent.
            let Some(rest) = line.strip_prefix("    ") else {
                continue;
            };
            if !rest.starts_with(|c: char| c.is_ascii_uppercase()) {
                continue;
            }
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            let mut kebab = String::new();
            for (i, c) in name.chars().enumerate() {
                if c.is_ascii_uppercase() && i > 0 {
                    kebab.push('-');
                }
                kebab.push(c.to_ascii_lowercase());
            }
            out.push(kebab);
        }
        out
    }

    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn the_table_names_every_varve_subcommand() {
        let mut declared = declared();
        declared.sort();
        let mut listed: Vec<String> = COMMANDS.iter().map(|(n, _)| n.to_string()).collect();
        listed.sort();
        assert_eq!(
            declared, listed,
            "varve's subcommands and varvecmds::COMMANDS disagree. Add the command to the table \
             (name, then the first sentence of its --help text)."
        );
    }

    // rivet: verifies REQ-AGENTDOCS-002
    #[test]
    fn the_table_is_sorted_and_every_entry_says_something() {
        for w in COMMANDS.windows(2) {
            assert!(w[0].0 < w[1].0, "{} before {}", w[0].0, w[1].0);
        }
        assert!(COMMANDS.iter().all(|(_, d)| d.len() > 20));
    }
}
