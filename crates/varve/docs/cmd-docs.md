# varve docs [topic]

This documentation, embedded in the binary (offline). `varve docs` lists topics; `varve docs <topic>` shows one; `--grep <q>` searches all topic bodies; `--format json` emits the list (or a single topic, with its body) as JSON for machine queries, modelled on `rivet docs`. `varve docs check --coverage` asserts every top-level subcommand has a topic (`--strict` exits non-zero on gaps — the CI gate).
