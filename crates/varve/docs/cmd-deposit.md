# varve deposit (CI)

Assembles the pinned per-tool artifacts into one layer manifest, embeds the release counter + issued-at, signs it into a DSSE envelope with the realm root, and writes the OCI image layout. The only way a layer comes into being; hand-edited manifests do not exist. Use --spec (TOML) or the individual flags.

```sh
varve deposit \
  --layer 2026.09.0 --channel qualified --counter 4 \
  --issued-at 2026-09-01T00:00:00Z \
  --key root.key --key-id acme-root-1 \
  --out ./layout \
  --tool "rivet@0.32.0=./dist/rivet"
```

Anything non-trivial uses a spec file — it is the only way to set a payload `kind`, source provenance, a runner, or an `[[include]]`:

```sh
varve deposit --spec deposit.toml --issued-at 2026-09-01T00:00:00Z --key root.key --out ./layout
```

The spec schema is in `varve docs config-reference`. Note `kind = "crate"` on a `[[tool]]` table is how a crate is deposited — there is no `[[crate]]`.

deposit writes a LOCAL oci-layout directory and does not publish; see `varve docs deploy`.

Deposit into a FRESH `--out` every time. Re-running deposit into a layout that already had a line-status, line-index or attestation attached succeeds — and silently drops every attached referrer, because deposit writes the whole `index.json`. The ordering of the producer pipeline is `varve docs ci`.
