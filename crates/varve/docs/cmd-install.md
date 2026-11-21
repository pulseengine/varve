# varve install [--from <src>] [--platform <triple>]

Resolves the project pin, fetches from the source (a realm registry, an oci:// reference, an oci-layout archive, or a manifests+blobs dir), verifies the signature and lays the layer down. Also auto-caches any baseline line-status the source carries. Fails closed on any verification failure.

**Digests are checked for this platform only.** An entry annotated for another target triple is skipped — not fetched, not hashed, not laid down, and never substituted (an Intel Mac is not handed the arm64 build). A tool that has *no* entry for this platform at all is named on stderr, one line each: *"note: layer L has no x86_64-apple-darwin build of loom; it will not be available here"*. A skipped entry of a tool that IS built for this platform is not mentioned. `varve verify` afterwards counts only what landed (`2 tool(s) match their signed digests`, exit 0). Use `--platform <triple>` to install a layer for a target other than this machine.

PulseEngine stopped building for Intel macOS (`x86_64-apple-darwin`) on 2026-11-20, so layers cut after that date can carry a tool for every platform but that one. On an Intel Mac, every command names the gap by platform:

- `varve which <tool>`, `varve run <tool>` and a shim fail with *"tool 'loom' has no build for x86_64-apple-darwin in layer L (it is built for: aarch64-apple-darwin, x86_64-unknown-linux-gnu)"*. A tool absent on every platform still fails with *"is not part of layer"*.
- A pin whose `tools` lists such a tool fails resolution with the same sentence and *"re-installing cannot help"* — not "incomplete, run `varve install`", which would land the same bytes again.

One more consequence worth knowing:

- `varve archive` on such a layer **succeeds, carrying one platform**: it exports the payloads this core actually holds, then reports what it omitted and names the platform the archive installs on. It does not fail, and you do not need per-platform layers. To archive for a platform other than this machine's, `varve install --platform <triple>` first and pass the same `--platform` to `archive`.

A layer whose entries name *no* entry for this platform is refused outright rather than installed empty.

A pin with `[toolchain.override.<tool>]` (REQ-OVERRIDE-001) also installs each override's layer, by digest, from the same sources and through the same verified path an `[[include]]` takes (`override synth: installed layer …`), then refuses — exit 1 — any override that cannot be honoured. A layer that fails verification is never installed. An override layer's digest is not consent to go below its line's high-water mark, so one below the mark is refused — also when it is in the store already, laid down before the mark moved past it, as `varve verify` refuses it. See `varve docs config-reference`.
