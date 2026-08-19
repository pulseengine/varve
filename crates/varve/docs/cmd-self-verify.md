# varve self-verify --archive <FILE> --envelope <FILE>

Verifies a varve release file against its signed SHA256SUMS envelope — the tool that gates the toolchain clearing its own gate.

Both arguments are **named flags**, not positionals; `varve self-verify a.tar.gz b.json` exits 2 with `unexpected argument`.

```sh
varve self-verify --archive "varve-$V-$T.tar.gz" --envelope SHA256SUMS.txt.dsse.json
```

`varve docs bootstrap` shows it in the full download-and-check sequence.
