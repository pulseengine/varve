# varve run [--varve <layer> | --with <tool>@<version>…] -- <tool or command> <args>

Dispatches a tool from the pinned layer with the layer identity in the environment (VARVE_LAYER, VARVE_LAYER_MANIFEST_DIGEST) so provenance tooling records which qualified set produced the output. --varve runs another installed layer without touching the pin.

The tool may be **realm-qualified** — `varve run bytecodealliance/wasm-tools -- --version` — to reach one specific provider where two realms of the composition ship the same name, including the one the pin did not choose. A bare name runs what the pin chose, never what installed last (see `varve docs composition`).

In a MIXED toolchain (`[toolchain.override.<tool>]`, REQ-OVERRIDE-001) an overridden tool runs from its override layer and every other tool from the pin. `VARVE_LAYER` stays the pinned layer, and `VARVE_OVERRIDES` names the mix — `tool=layer@digest`, comma-separated, sorted by tool — for every tool run in the project. In a pure project `VARVE_OVERRIDES` is removed from the environment, so an inherited value never passes for this toolchain's. An override that cannot be honoured is refused before anything runs, exit 1.

Every address of an overridden tool runs the override: `synth` and the pin's own `acme/synth`; another realm's `other/synth` is refused, naming the override. A runner contract comes from the layer whose binary runs, and so does the runner it names (REQ-RUNNER-001): an overridden tool runs through the override layer's OWN runner, never the pin's. An override layer whose tool names a runner that layer does not carry is refused — at `install`, before anything is laid down, and before exec — naming the layer and the runner. Overriding a runner itself does not change what runs the pin's own tools: they keep the pinned composition's runner. `--varve <layer>` is refused in a project with overrides: a one-off layer plus the project's overrides is a mix nobody declared.

## One command with another version of a tool: `--with`

```sh
varve run --with synth@0.57.0 -- synth build.yaml
varve run --with synth@0.57.0 --with loom@0.9.0 -- make bench
```

`--with <tool>@<version>` (REQ-RUNWITH-001) runs this one command as though varve.toml carried a `[toolchain.override.<tool>]` naming the layer that ships that version, and every other tool from the pin. The command may be a tool of the layer or any program — a script, `make` — and every call to the tool by bare name anywhere in the command's process tree gets the `--with` version (see *How a script reaches the override* below). **Nothing persists**: varve.toml, the store, the anti-rollback marks and the project are byte-identical afterwards, and the next command runs the pin.

The version is resolved to a layer id and digest **only among layers already installed from the pin's realm** — the store's partition for that realm's trust root — by the `eu.pulseengine.tool.version` the layer's signed manifest declares for the tool on this platform. The match is exact: no ranges, no "latest". `--with` never fetches. To make a version available, install a layer that carries it the one way anything reaches the store — pin it (for example as an override) and run `varve install`.

Once a layer is chosen, the run obeys every rule an override in varve.toml obeys, and is refused before anything runs where one would be: a tool the pinned composition does not dispatch here (an override replaces, it never adds), a layer installed for another platform or on another channel than the pin's, a tool the layer does not declare or no longer has on disk, a runner the layer does not carry. A refusal of the chosen layer names the in-memory `[toolchain.override.<tool>]` it was applied as.

The command's environment says what it ran with: `VARVE_WITH` is what was asked — `tool@version`, comma-separated, sorted by tool — and `VARVE_OVERRIDES` is what it resolved to, in the `tool=layer@digest` form, including any override varve.toml declares. `VARVE_LAYER` stays the pinned layer. A run without `--with` removes an inherited `VARVE_WITH`.

Also refused, exit 1, nothing run:

- **No installed layer carries the version.** The refusal says so, lists the versions of the tool that are installed and their layers, and how to get one: the realm's line index names layers, not tool versions, so find the layer in the realm's release notes, pin it and `varve install`.
- **The version is installed only under another trust root** (another realm's partition, or the realmless store). The refusal prints the exact varve.toml lines — `[toolchain.override.<tool>]` with that layer and digest — which `varve install` would then fetch from the pin's realm and verify against its root, failing if the realm did not sign it.
- **Several installed layers carry the version and do not run the same bytes** — the tool entry's signed digest, and for a runnered tool its runner contract and the runner's digest. The refusal lists them; name the one you mean in varve.toml. When they all run the same bytes, the least by layer id and then digest is chosen, whatever order they were installed in.
- **The same tool twice** (`--with synth@… --with SYNTH@…`): one `--with` per tool.
- **A tool varve.toml already overrides**: an override of an override. `--with` does not replace the reviewed override; change varve.toml or run without `--with`. An override of ANOTHER tool in varve.toml applies beside `--with`.
- **Beside `--varve`**: one layer swapped whole plus a tool from another is a toolchain nobody declared.

- **A command the layer holds or carries but does not dispatch** (a held payload, a tool the pin's `tools` list leaves out): it is never run from outside the layer.

### How a script reaches the override

With `--with`, `varve run` does not exec. It creates a **private shim directory** with mkdtemp under `TMPDIR` — mode 0700, an unpredictable name, never under `VARVE_ROOT` or the project — and starts the command as a child with that directory **first on PATH**. For each `--with` tool the directory holds a small wrapper that execs `varve run --with-shim-dir <that directory> -- <tool>`, so a call by bare name from the command, or from anything it starts, reaches the wrapper before any other `synth` on PATH. The run waits for the child, removes the directory, and exits with the child's status — 128 + N for a child killed by signal N. SIGINT, SIGTERM and SIGHUP sent to `varve` are forwarded to the child, and the directory is removed then too. A command that cannot be started is refused, exit 1, and the directory is removed.

The wrapper names its directory **in its own text**. No environment variable is read to find an override, so an inherited variable cannot change what any shim runs, and a regular shim never consults the private directory. The directory also holds what the run resolved (`with.json`: the project's varve.toml, each tool's layer and digest, what was asked) and a lock that the run holds for its whole life. A wrapper is honoured only while that lock is held:

- **The run is alive:** the wrapper's varve checks the directory is the caller's own and 0700, then re-verifies the recorded override against the store exactly as an override in varve.toml — the tool the pin dispatches, the digest installed in this realm, its channel and platform, the tool and runner in that layer — and execs the tool. It creates no directory and starts no child, so nested calls do not nest. An edited record can name only what the pin could have overridden anyway, and a record varve cannot read whole is refused.
- **In another project** (the command `cd`s into a directory with another varve.toml), the wrapper runs the tool as `varve run` would there: that project's pin decides, and the override does not apply.
- **After the run ends**, the directory is gone. If `varve` itself is killed with SIGKILL, it cannot remove the directory and the directory leaks in `TMPDIR`. Its lock died with the process, so its wrappers refuse — `… outlived the varve run --with that made it` — without reading the record, edited or not. Only processes that inherited the child's PATH could reach it at all. Remove a leaked `varve-with-*` directory by hand.

Without `--with`, `varve run` execs the tool as before, and no directory is made.
