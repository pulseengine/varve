# Binary WIT packages for the `export-wit` system gate

Two packages, one depending on the other, as a layer carries them: **flat**,
one payload per `namespace:name@version`, each encoded on its own
(REQ-WIT-001 clause 1). `acme:app@0.3.0` imports `acme:base/clock@2.0.0`, and
nothing outside the package bytes says so — which is the property the gate
exercises: `export-wit` is asked for `acme:app` alone and must write
`acme:base` beside it.

They are committed rather than generated at run time so the gate needs no
`wasm-tools` on the runner, and so the bytes the export is compared against
are fixed. The sources are here beside them; regenerate with:

```sh
d=$(mktemp -d) && mkdir -p "$d/deps"
cp acme-base.wit "$d/deps/" && cp acme-app.wit "$d/"
wasm-tools component wit "$d" --wasm -o acme-app-0.3.0.wasm
rm -rf "$d"/* && cp acme-base.wit "$d/"
wasm-tools component wit "$d" --wasm -o acme-base-2.0.0.wasm
```

Produced with `wasm-tools` 1.259.0 (7fc33f279 2026-09-10) from the `pulseengine` realm.
