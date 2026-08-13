# varve deposit (CI)

Assembles the pinned per-tool artifacts into one layer manifest, embeds the release counter + issued-at, signs it into a DSSE envelope with the realm root, and writes the OCI image layout. The only way a layer comes into being; hand-edited manifests do not exist. Use --spec (TOML) or the individual flags.
