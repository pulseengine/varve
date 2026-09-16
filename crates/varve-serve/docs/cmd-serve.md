# varve-serve

Read the documentation the pinned layer carries, copying nothing.

```sh
varve-serve                      # one document: nothing to type
varve-serve --select handbook    # several: name one
varve-serve --port 8080          # somewhere else; --port 0 picks a free one
varve-serve --layer 2026.09.3    # a layer other than the pin
varve-serve --check              # what would be served, without listening
varve-serve --docs security      # this program's own documentation
```

## Why not just open the file?

A generated documentation bundle fetches assets at runtime, and browsers block
that under `file://`. varve's own traceability bundle loads mermaid, which calls
`fetch()` — open an exported `index.html` directly and the diagrams silently do
not render. Nothing errors. You simply get less than the document, and no
indication that you did.

rustdoc's search has the same shape.

## Why not `varve serve`?

`varve` is the program that decides whether a toolchain can be trusted. Giving
it a listening socket would widen the surface of exactly the thing whose
smallness is the argument. So the viewer ships beside it: one repository, one
release, one signature — and a realm can carry it or leave it out.

See `varve-serve --docs security` for what that separation does and does not
buy you.

## It reads the store, it does not copy

| | `varve-serve` | `varve export-docs` |
|---|---|---|
| writes anything | no | yes, a full copy |
| costs disk | nothing | a second copy of the document |
| stale when the pin moves | never | yes — hence the stamp |
| use it for | reading | handing to someone, a CI artifact, printing |

The store keeps the archive exactly as its producer signed it and never unpacks
it, because the stored bytes have to stay identical to what the signature
covers. This reads out of that archive directly. When the pin moves, so does
what is served — there is nothing to go stale, and nothing to remember to
re-export.

## The selector is optional, once

With one document there is nothing to type: you already said which layer you
wanted by pinning it, and naming the document again is asking twice. With
several, `--select` is required — varve-serve refuses rather than guessing,
because opening the wrong document silently is worse than a question, and the
refusal lists what the layer carries.

## What it will not serve

A `pdf`, `markdown` or `reqif` document is a single file, not a site. There is
nothing to serve out of it, and pointing a browser at one blob is worse than
saying so — you want it on disk:

```sh
varve export-docs --out ./doc --select handbook
```

## `--check`

Prints what would be served — the document, its format, how many pages, and the
declared entry — then exits without binding a port. This is the form for CI: a
gate can assert that a layer's documentation is readable without leaving a
process listening.

## The entry point is declared, not guessed

`/` goes to the entry the manifest declared and that the deposit verified
exists, not to whatever `index.html` is nearest. varve's traceability bundle
carries `eu-ai-act/index.html` and `artifacts/index.html` beside its root page;
a viewer that guessed would have three candidates and no way to choose.

If the payload and its annotation ever disagree, that is reported plainly rather
than served as a 404 at the front door: the bytes verify, so what is wrong is
not corruption but a manifest describing a document it does not carry.
