# varve export-docs

Where is the documentation for the versions this layer pins?

```sh
varve export-docs --out ./doc                   # one document: no selector needed
varve export-docs --out ./doc --select handbook # several: name one
```

A layer pins exact versions and, on its own, says nothing about how to use
them. Tools that embed their own documentation answer for themselves — `varve
docs` and `rivet docs` work offline, at the version installed. **This command is
for the documentation nothing can be asked for**: the handbook, the traceability
report, the rustdoc for a crate you are consuming air-gapped.

## Export, or read in place?

Two different questions, and it is worth picking the right one.

| | `varve export-docs` | `varve-serve` |
|---|---|---|
| writes a copy | yes | no |
| costs disk | yes, a second copy | nothing |
| goes stale when the pin moves | yes — hence the stamp | no |
| use it for | handing to someone, a CI artifact, printing | reading |

The store keeps the archive exactly as its producer signed it and **never
unpacks it**. That is not tidiness: the stored bytes have to stay identical to
what the signature covers, or `varve verify` cannot re-derive the digest. So
reading a document does not require exporting one — `varve-serve` reads straight
out of the verified store.

## The selector is optional, once

With one document, naming it is asking twice: you already said which layer you
wanted by pinning it. With several, the selector is **required** — varve refuses
rather than guessing, because opening the wrong document silently is worse than
a question. The refusal lists what the layer carries, so your next command has
the right handle.

## Format is declared, not guessed

Every `docs` payload carries a signed format:

| | what it is | exported as |
|---|---|---|
| `html` | a multi-file site | a directory |
| `rustdoc` | `cargo doc` output | a directory |
| `pdf` | one file | `<name>-<version>.pdf` |
| `markdown` | source text | `<name>-<version>.md` |
| `reqif` | a requirements-tool interchange file | `<name>-<version>.reqif` |

varve never infers this from the file name. An extension-based guess is right
almost always, which is precisely what makes the one wrong case arrive as a
puzzle instead of an error — and the format is what decides how the document is
opened.

`rustdoc` is its own format rather than `html` because it is generated rather
than authored, versions with the crate it documents, and answers a different
question. "Show me the API" is not "show me the handbook", and that only works
if they are different values.

## `file://` will not do for a tree

A tree document generally fetches assets at runtime, and browsers block that
under `file://`. varve's own traceability bundle loads mermaid, which calls
`fetch()` — open the exported `index.html` directly and the diagrams silently do
not render. Nothing errors; you just get less than the document.

So serve it:

```sh
varve-serve --dir ./doc
```

## The stamp

An export is a **copy**, and a copy is a fork the moment the pin advances. So
the directory is stamped with the layer it came from, and `varve verify` reports
an export left behind by a pin that moved on (REQ-EXPORT-SYNC-001). A document
that quietly describes last month's toolchain is the failure this prevents.

`varve-serve` needs no stamp — there is nothing to go stale.

## See also

- `varve docs inspect` — every payload in the layer, including documents
- `varve docs sdk` — the other tree-shaped payload, and why it is relocated
  while a document is not
