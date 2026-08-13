# Air-gapped operation

varve is built for environments with no network to a public registry or
transparency log — the safety-critical norm. Install runs from an archived core
(`varve archive` / an oci-layout) with verification unchanged; the Cargo/Bazel
exports produce local, offline-consumable byte sources; and the trust root is
pinned, not fetched. A varve operation must never REQUIRE reaching a public API.
This is the core thesis: a phone-home that fails on a network blip is exactly
the fragility varve exists to remove.
