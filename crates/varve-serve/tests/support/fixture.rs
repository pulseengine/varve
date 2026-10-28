//! A signed, installed layer built the way a real one is: `deposit`, then
//! `install`, through varve-core's own entry points.
//!
//! Shared by the library's unit tests and the binary's integration tests
//! through `#[path]`, so the two cannot drift. It lives under `tests/` and not
//! `src/` on purpose: it is test support, and putting it in `src/` would make
//! it production code the mutation gate has to decide about.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use varve_core::deposit::DepositInclude;
use varve_core::install::{InstallPolicy, install};
use varve_core::rollback::HighWaterMarks;
use varve_core::source::MemorySource;
use varve_core::store::{Store, manifest_digest};
use varve_core::verify::{PinnedKeyVerifier, generate_root_keypair};
use varve_core::{DepositSpec, DepositTool, PayloadKind, Pin};

pub struct Fx {
    pub tmp: tempfile::TempDir,
    /// `VARVE_ROOT`.
    pub root: PathBuf,
    /// The project directory holding `varve.toml`.
    pub project: PathBuf,
    /// File holding the hex trust root (`VARVE_TRUST_ROOT`).
    pub trust_root: PathBuf,
    pub store: Store,
    pub digest: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// A tool whose bytes are a shell script.
pub fn script_tool(name: &str, version: &str, body: &str) -> DepositTool {
    DepositTool {
        name: name.into(),
        version: version.into(),
        platform: None,
        target: None,
        bytes: format!("#!/bin/sh\n{body}\n").into_bytes(),
        source: None,
        runner: None,
        kind: None,
        sdk_prefix: None,
        docs_format: None,
        docs_entry: None,
        docs_title: None,
        docs_documents: None,
        libc: None,
    }
}

/// A `.tar.gz` of `files`.
pub fn tar_gz(files: &[(&str, &str)]) -> Vec<u8> {
    let enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);
    for (path, body) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, path, body.as_bytes()).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

/// A rustdoc-shaped docs payload documenting `documents`.
pub fn docs_tool(name: &str, documents: Option<&str>, files: &[(&str, &str)]) -> DepositTool {
    DepositTool {
        kind: Some(PayloadKind::Docs),
        bytes: tar_gz(files),
        docs_format: Some("rustdoc".into()),
        docs_entry: Some(files[0].0.to_string()),
        docs_title: Some(format!("{name} API")),
        docs_documents: documents.map(str::to_string),
        ..script_tool(name, "1.2.3", "")
    }
}

/// A held payload of some other kind.
pub fn held_tool(name: &str, version: &str, kind: PayloadKind) -> DepositTool {
    DepositTool {
        kind: Some(kind),
        bytes: format!("{name}-bytes").into_bytes(),
        ..script_tool(name, version, "")
    }
}

pub fn page(title: &str) -> String {
    format!("<html><head><title>{title}</title></head><body>{title}</body></html>")
}

fn source_at(layout: &Path) -> MemorySource {
    let envelope = std::fs::read(layout.join("layer.dsse.json")).unwrap_or_else(|_| {
        for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
            let b = std::fs::read(e.unwrap().path()).unwrap();
            if serde_json::from_slice::<serde_json::Value>(&b)
                .ok()
                .and_then(|v| v.get("payload").cloned())
                .is_some()
            {
                return b;
            }
        }
        panic!("no envelope in {}", layout.display())
    });
    let mut source = MemorySource::new().with_manifest(&envelope);
    for e in std::fs::read_dir(layout.join("blobs/sha256")).unwrap() {
        let b = std::fs::read(e.unwrap().path()).unwrap();
        source = source.with_blob(&manifest_digest(&b), &b);
    }
    source
}

/// Deposit `tools` as layer `2026.10.1` of an unnamed realm and install it for
/// the host platform.
pub fn install_layer(tools: Vec<DepositTool>) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let store = Store::at(&root);
    let (sk, pk) = generate_root_keypair();
    let layout = tmp.path().join("layout");
    let outcome = varve_core::deposit(
        &DepositSpec {
            includes: Vec::<DepositInclude>::new(),
            layer: "2026.10.1".parse().unwrap(),
            channel: "rolling".into(),
            counter: 1,
            issued_at: "2026-10-20T00:00:00Z".into(),
            tools,
        },
        &sk,
        "fixture-1",
        &layout,
    )
    .expect("deposits");
    let pin_text =
        "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"2026.10.1\"\n";
    std::fs::write(project.join("varve.toml"), pin_text).unwrap();
    let pin = Pin::parse(pin_text, "varve.toml").unwrap();
    let mut marks = HighWaterMarks::load(&root).unwrap();
    let verifier = PinnedKeyVerifier::from_public_key_bytes(&pk).unwrap();
    install(
        &pin,
        &source_at(&layout),
        &verifier,
        &store,
        &mut marks,
        &InstallPolicy {
            index: None,
            now: "2026-10-20T00:00:00Z",
            staleness_threshold_days: 3650,
            platform: &varve_core::host_platform(),
        },
    )
    .expect("installs");
    let trust_root = tmp.path().join("trust-root.hex");
    std::fs::write(
        &trust_root,
        pk.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    )
    .unwrap();
    Fx {
        tmp,
        root,
        project,
        trust_root,
        store,
        digest: outcome.digest,
        public_key: pk,
        secret_key: sk,
    }
}

impl Fx {
    /// Deposit and install ANOTHER layer of the same line into the same store,
    /// signed by the same root, without touching the project's pin.
    pub fn install_another(&self, layer: &str, counter: u64, tools: Vec<DepositTool>) {
        let layout = self.tmp.path().join(format!("layout-{layer}"));
        varve_core::deposit(
            &DepositSpec {
                includes: Vec::<DepositInclude>::new(),
                layer: layer.parse().unwrap(),
                channel: "rolling".into(),
                counter,
                issued_at: "2026-10-21T00:00:00Z".into(),
                tools,
            },
            &self.secret_key,
            "fixture-1",
            &layout,
        )
        .expect("deposits");
        let text = format!(
            "manifest-version = 1\n[toolchain]\nchannel = \"rolling\"\nlayer = \"{layer}\"\n"
        );
        let pin = Pin::parse(&text, "varve.toml").unwrap();
        let mut marks = HighWaterMarks::load(&self.root).unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&self.public_key).unwrap();
        install(
            &pin,
            &source_at(&layout),
            &verifier,
            &self.store,
            &mut marks,
            &InstallPolicy {
                index: None,
                now: "2026-10-21T00:00:00Z",
                staleness_threshold_days: 3650,
                platform: &varve_core::host_platform(),
            },
        )
        .expect("installs");
    }

    /// The verified composition of the installed layer, as `main` walks it.
    pub fn composed(&self) -> Vec<varve_core::compose::ComposedLayer> {
        let entry = self.store.get(&self.digest).unwrap().unwrap();
        let verifier = PinnedKeyVerifier::from_public_key_bytes(&self.public_key).unwrap();
        varve_core::compose::walk_installed(
            &self.store,
            &entry,
            &verifier,
            "(this project)",
            &Default::default(),
            &varve_core::host_platform(),
        )
        .unwrap()
    }

    /// The directory a tool's bytes were laid down in.
    pub fn tool_file(&self, name: &str) -> PathBuf {
        self.root
            .join("core")
            .join(self.digest.replace(':', "-"))
            .join("bin")
            .join(name)
    }

    /// Run the real binary against this fixture, with only what it needs in
    /// its environment.
    pub fn run(&self, bin: &str, args: &[&str]) -> std::process::Output {
        std::process::Command::new(bin)
            .args(args)
            .current_dir(&self.project)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.tmp.path())
            .env("TMPDIR", self.tmp.path())
            .env("VARVE_ROOT", &self.root)
            .env("VARVE_TRUST_ROOT", &self.trust_root)
            .output()
            .expect("runs")
    }
}
