# varve-producer plan

The work a deposit would do, without fetching anything.

```sh
varve-producer plan --manifest layer.toml
varve-producer plan --platform x86_64-unknown-linux-gnu
```

Reads `layer.toml` directly. There is no `TARBALL_TOOLS`/`WSC_VERSION`
environment encoding to corrupt, and no limit of one raw-per-platform tool —
that encoding cannot express a payload `layout` at all, so an `sdk` entry
translated through it silently became an ordinary tarball and the tree was mined
for a binary.

Run it before a deposit to see which release asset each payload resolves to. A
reviewer reading a run log should be able to see a layer's contents without
decoding an environment variable.
