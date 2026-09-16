# varve-producer scan

Which pinned payloads have a newer upstream release?

```sh
varve-producer scan                          # reads ./layer.toml
varve-producer scan --manifest realm.toml
varve-producer scan --format json            # for a gate
```

Prints one `name<TAB>pinned<TAB>latest` line per payload that moved, and
`nothing moved` when none did.

## Pins come from the manifest, and nowhere else

The scanner this replaced read them out of a workflow file's env-var encoding
and broke silently when the realm moved to its own repository. A second place
the realm is defined is a place the two disagree.

## An upstream that cannot be ASKED is an error

Not "nothing moved". The distinction is the whole design:

```
error: 2 upstream(s) could not be asked what they have published:
  pulseengine/meld: HTTP 403: rate limited
  ...
Refusing to report movement from an incomplete scan.
```

A scanner that reported no movement because it could not ask would **freeze the
realm while every check stayed green** — releases would stop arriving and nobody
would be told. Exit 1, loudly, is the cheaper failure.

A repository missing from the answers counts the same way: a lookup loop that
skips one leaves the result short, and an under-report reads exactly like calm.

## GitHub Enterprise

`GH_HOST` is what `gh` itself uses, so varve passes the same variable rather
than inventing a second one. Every lookup carries it. On public GitHub no host
override is set — setting one there is how a working setup starts failing for a
reason nobody can see.

```sh
GH_HOST=github.acme.example varve-producer scan
```

## One query per repository

Not per payload. varve ships `varve` and `varve-producer` from one repository,
and at four scans an hour a duplicate query is the difference between
comfortable and rate-limited.
