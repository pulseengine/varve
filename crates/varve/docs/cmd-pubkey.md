# varve pubkey <KEY>

Prints the public half of a signing key, in exactly the form a realm's `trust-root` accepts — bare on stdout, so it composes:

```sh
trust-root = "$(varve pubkey root.key)"
```

It refuses a key whose halves disagree, because such a key signs happily and produces layers no trust root can ever verify. That check is the same one `deposit` applies before signing.
