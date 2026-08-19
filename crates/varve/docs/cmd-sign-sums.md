# varve sign-sums (CI)

Signs a release `SHA256SUMS.txt` into the DSSE envelope `varve self-verify`
consumes — the producing half of self-verification, run by the release
pipeline of varve itself and of anything else distributed the same way. The
sums file is the ordinary `sha256sum` format: one `<hex>  <filename>` line
per release artifact.

```sh
sha256sum varve-*.tar.gz > SHA256SUMS.txt
varve sign-sums --sums SHA256SUMS.txt \
                --key root.key --key-id varve-root-1 \
                --out SHA256SUMS.txt.dsse.json
# signed release sums -> SHA256SUMS.txt.dsse.json
```

Publish BOTH files as release assets. The consuming half is:

```sh
varve self-verify --archive varve-x86_64-unknown-linux-gnu.tar.gz \
                  --envelope SHA256SUMS.txt.dsse.json
```

which verifies the envelope against the pinned trust root, finds the file's
name in the signed sums, and re-hashes the bytes — the tool that gates the
toolchain clearing its own gate (`varve docs self-verify`, and `varve docs
bootstrap` for where this sits in the install story).

A key whose halves disagree is refused before signing, as on every producing
path: an envelope no trust root could ever verify must not be produced with
exit 0. In CI, `--key /dev/stdin` accepts the key from a pipe — see `varve
docs ci`.

## Limits worth knowing

* The envelope binds the sums under their own payload type: a signed
  SHA256SUMS cannot be replayed as a layer manifest, a line-status, or a
  line-index.
* `self-verify` matches by FILE NAME within the signed sums — rename a
  release artifact and verification fails until the name matches an entry.
* This signs release files, not layers. Layers are signed by `varve deposit`
  and never by hand.
