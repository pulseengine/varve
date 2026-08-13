//! Dispatch-path cost (REQ-PERF-001).
//!
//! `resolve` runs on EVERY shim dispatch — every `cargo`, `rivet`, `synth`
//! invocation — so its cost is the tax on using varve at all. This benchmark
//! makes the number tracked rather than folklore, and pins the complexity
//! claim: a digest-carrying pin resolves in constant time, while a name-only
//! pin is linear in the number of installed layers (`Store::list` parses each
//! `layer.json` to recover its identity). Compare `name_only/3` against
//! `name_only/200` to see the slope the docs promise.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use varve_core::{Pin, Store};

/// Lay down `n` layers, returning the store dir and one installed digest.
fn store_with(n: usize, dir: &std::path::Path) -> (Store, String) {
    let store = Store::at(dir);
    let mut first = String::new();
    for i in 0..n {
        let layer = format!("2026.{:02}.{}", (i % 12) + 1, i / 12);
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","artifactType":"application/vnd.pulseengine.varve.layer.v1+json","annotations":{{"eu.pulseengine.varve.layer":"{layer}","eu.pulseengine.varve.channel":"qualified"}},"manifests":[]}}"#
        );
        let d = store
            .lay_down(manifest.as_bytes(), &[("probe", b"x")])
            .unwrap();
        if i == 0 {
            first = d;
        }
    }
    (store, first)
}

fn bench_resolve(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve");
    for n in [3usize, 50, 200] {
        let tmp = tempfile::tempdir().unwrap();
        let (store, digest) = store_with(n, tmp.path());
        // The pinned layer is always the first one laid down.
        let entry = store.get(&digest).unwrap().unwrap();
        let layer = entry.layer.to_string();

        // Name-only pin: linear in installed layers (documented, not hidden).
        let by_name = Pin::parse(
            &format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"{layer}\"\n"
            ),
            "bench",
        )
        .unwrap();
        group.bench_with_input(BenchmarkId::new("name_only", n), &n, |b, _| {
            b.iter(|| varve_core::resolve(&by_name, &store).unwrap())
        });

        // Digest pin: constant time, whatever the store holds.
        let by_digest = Pin::parse(
            &format!(
                "manifest-version = 1\n[toolchain]\nchannel = \"qualified\"\nlayer = \"{layer}\"\ndigest = \"{digest}\"\n"
            ),
            "bench",
        )
        .unwrap();
        group.bench_with_input(BenchmarkId::new("digest", n), &n, |b, _| {
            b.iter(|| varve_core::resolve(&by_digest, &store).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, bench_resolve);
criterion_main!(benches);
