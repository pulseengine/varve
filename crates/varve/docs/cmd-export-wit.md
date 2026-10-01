# export-wit — compose a WIT package and its dependencies

A layer carries WIT packages **flat**: one payload per
`namespace:name@version`, so `wasi:io@0.2.0` exists once in a layer, at one
digest, however many packages depend on it.

A consumer does not want them flat. They want one package treated as top
level, with everything it needs beside it. `export-wit` composes that.

```sh
varve export-wit --package 'acme:app@0.3.0' --out ./wit
```

```
exported 2 package(s) for acme:app@0.3.0 to /w/wit
  acme:base@2.0.0
  acme:app@0.3.0
```

The closure comes from the packages themselves — a WIT package declares what
it imports — not from a list in `layer.toml`. A second list would be a second
thing to keep in step.

## The layout is `wkg`'s, and the bytes are untouched

Each package lands at `<namespace>/<name>/<version>.wasm`, which is exactly
what `wkg`'s `local` backend reads:

```
wit/
├── acme/
│   ├── app/0.3.0.wasm
│   └── base/2.0.0.wasm
```

This is a **copy, not a conversion**. The bytes you build against are
byte-identical to the bytes varve verified, so the digest in the layer and the
digest on disk are the same number. A re-encode would make them different
numbers for the same package.

Point `wkg` at it with `--registry`, which prints the stanza rather than
editing your configuration:

```sh
varve export-wit --package 'acme:app@0.3.0' --out ./wit --registry acme.example
```

```toml
[registry."acme.example".local]
root = "/w/wit"
```

## Offline, and that is the point

Every package comes from the verified store. Nothing resolves over the
network — which is what makes this usable where `wkg_wit_deps` pointed at a
remote registry is not.

## A missing dependency is a refusal, not a smaller tree

If the layer does not carry something the closure names, `export-wit` writes
**nothing** and says which package is missing. A tree with one package absent
parses far enough to fail later inside `wit-bindgen`, with an error about an
*interface* — and you would then debug your WIT instead of your layer.

The same holds for bytes that cannot be resolved after the closure is
computed: every package is read before any is written.

## What it does not do

**It does not emit WIT text, and that matters for which tool you are
feeding.** The payload is the binary package the ecosystem publishes and pins,
and that is what is written. `wkg` and `rules_wasm_component`'s `wkg_wit_deps`
read this tree directly. **`wit-bindgen`, `cargo-component` and the vendored
`rules_wasm_component` path want a `wit/` source tree instead**, and this
export does not produce one — decode it yourself with `wasm-tools component wit
<file>`, which is in the realm.

Printing text from varve would mean carrying a WIT *writer* in the production
path to produce a form varve does not sign; the decoder varve carries is
deliberately read-only. Whether that trade is worth making is open — see #220
for the measurement and DD-036 for the decision. What it costs today in
auditability — a signed artifact a human cannot read without a second tool —
was taken with open eyes.

**It does not edit your tool configuration.** `--registry` prints a stanza;
where it goes is yours.

**It is not a link.** This writes a tree you own, can commit, and can hand to
an assessor six months later. Pointing a resolver at the store without a copy
is a separate mechanism and is not built yet — deliberately, see
`varve docs composition` and DD-036. When it lands it uses this same layout,
so nothing you configure here has to change.

See also: `varve docs inspect`, `varve docs composition`.
