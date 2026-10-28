# varve-serve ask

One narrow question, answered with pointers into verified material.

```sh
varve-serve ask "sign wasm module"
varve-serve ask Store type --format json --limit 3
```

The question is words; no quoting is needed. Each hit carries a stable `id`, its
kind, a title, the `layer`, the payload `digest` where there is one, and `read`:
the exact command that shows the whole page or topic. It never returns the text
that matched.

## What is searched

- documentation payload pages (title and path), read from the verified store;
- every pinned tool's subcommands, and its one-line overview with its warning;
- the text of each tool's built-in docs topics, where its `--help` advertised
  `docs`;
- `varve`'s own subcommands (`varve export-vsix` and the rest);
- held payloads, with the command that gets them out;
- names a tool's warning points at that the pin does not carry (`kiln`, for
  `kilnd`), so asking for one says it is not here.

The index is built at query time from verified bytes and thrown away. It is never
signed and never shipped.

## Ranking

Lexical and deliberately plain.

- **Stopwords are dropped**, so "where is the Store type defined" ranks as
  "Store type". This was the largest single gain in measurement.
- **An exact item beats its module**: `struct.Store.html` for "Store" outranks the
  pages that are merely in `varve_core::store`.
- **A tool the question names** raises that tool's hits.
- Ties break by kind, then id, so two runs print the same bytes.

`--limit N` (default 5) is how many hits to print; `--format json` prints them
as JSON.

## No hits

It says so and points at `varve inspect`, which lists everything the pin holds.

## Offline, and what it runs

No network. It runs the same pinned binaries `context` does, in the same box and
with the same cache, so after one `context` it runs nothing. If any layer fails
verification it exits non-zero with empty stdout.
