# varve install [--from <src>] [--platform <triple>]

Resolves the project pin, fetches from the source (a realm registry, an oci:// reference, an oci-layout archive, or a manifests+blobs dir), verifies the signature and lays the layer down. Also auto-caches any baseline line-status the source carries. Fails closed on any verification failure.

**Digests are checked for this platform only.** An entry annotated for another target triple is skipped — not fetched, not hashed, not laid down — and nothing is printed about it. A three-entry layer carrying one Linux tool installs on macOS reporting two, and `varve verify` afterwards reports `2 tool(s) match their signed digests`, exit 0. Neither command mentions the third. Use `--platform <triple>` to install a layer for a target other than this machine.

Two consequences worth knowing before you rely on the count:

- `varve which <tool>` on a skipped entry fails with *"is not part of layer … as pinned here"*, which reads like the layer lacks the tool rather than lacking it *here*.
- `varve archive` on such a layer **succeeds, carrying one platform**: it exports the payloads this core actually holds, then reports what it omitted and names the platform the archive installs on. It does not fail, and you do not need per-platform layers. To archive for a platform other than this machine's, `varve install --platform <triple>` first and pass the same `--platform` to `archive`.

A layer whose entries name *no* entry for this platform is refused outright rather than installed empty.
