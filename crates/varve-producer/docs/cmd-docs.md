# varve-producer docs

This documentation, compiled into the binary.

```sh
varve-producer docs                    # list topics
varve-producer docs scan               # one topic
varve-producer docs --grep enterprise  # search
varve-producer docs --format json      # for tooling
varve-producer docs check --coverage --strict
```

No files, no network — it works air-gapped, which is where a producer often
runs.

## Why the producer carries its own

varve carries its documentation and gates it: every subcommand must have a
topic, mechanically, so a new one cannot ship undocumented. That gate covered
**one of two shipped binaries**. varve-producer had nine subcommands and zero
topics, while being the program that other repositories' CI actually runs.

Documenting it inside `varve docs` would not have fixed that. A CI job holding
the producer may not hold varve, and sending someone to a different binary for
the manual is the friction this exists to remove.

## The coverage gate

`docs check --coverage` enumerates this CLI's own subcommands and reports any
lacking a topic. `--strict` exits non-zero, which is what a CI gate reads.

The invariant is mechanical rather than editorial: a new subcommand fails the
build until someone writes down what it does.
