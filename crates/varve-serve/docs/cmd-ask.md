# varve-serve ask

One narrow question, answered with pointers into verified material.

```sh
varve-serve ask "sign wasm module"
varve-serve ask Store type --format json --limit 3
```

The question is words; no quoting is needed. Each hit carries a stable `id`, its
kind, a title (for a docs page, its path), the `layer`, the payload `digest` where there is one, and `read`:
the exact command that shows the whole page or topic. It never returns the text
that matched.

## What is searched

- documentation payload pages (Markdown, HTML and rustdoc HTML): title, path and
  the page's TEXT, ranked by best line like topics, read from the verified store.
  For HTML the markup, script and style are dropped, and where a page has a
  `<main>` element (rustdoc does) only its content is searched, not the sidebar.
  At most the first 512 KiB of a page is searched. A hit points at the page and
  names the question's own words that one of its lines holds. For a docs-page
  hit what is printed is only: the page's path inside its payload (shown where
  other hits show a title), the score, the question's own words that a line
  holds, and the `read` command. The page's own `<title>` or heading is NOT
  shown, because a producer wrote it and a title is the line an injected
  instruction would choose; it still counts when ranking. The hit's `title`
  field in `--format json` is that same path. The path is a producer's choice
  too, so it is printed (in the title, the `id` and the `read` command) only
  when every character is one of `A-Z a-z 0-9 . _ / -` and it is at most 200
  bytes; otherwise the page is shown as a handle, `page-` and 12 hex digits of
  the SHA-256 of its path, which `varve-serve page` opens like the path. The
  limit that remains: a safe path can still spell words
  (`IGNORE_PREVIOUS_INSTRUCTIONS.md`). A pointer names the file; it does not
  vouch for it. Read the page with `read` when you need its text;
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
