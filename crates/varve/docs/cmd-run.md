# varve run [--varve <layer>] -- <tool> <args>

Dispatches a tool from the pinned layer with the layer identity in the environment (VARVE_LAYER, VARVE_LAYER_MANIFEST_DIGEST) so provenance tooling records which qualified set produced the output. --varve runs another installed layer without touching the pin.

The tool may be **realm-qualified** — `varve run bytecodealliance/wasm-tools -- --version` — to reach one specific provider where two realms of the composition ship the same name, including the one the pin did not choose. A bare name runs what the pin chose, never what installed last (see `varve docs composition`).

In a MIXED toolchain (`[toolchain.override.<tool>]`, REQ-OVERRIDE-001) an overridden tool runs from its override layer and every other tool from the pin. `VARVE_LAYER` stays the pinned layer, and `VARVE_OVERRIDES` names the mix — `tool=layer@digest`, comma-separated, sorted by tool — for every tool run in the project. In a pure project `VARVE_OVERRIDES` is removed from the environment, so an inherited value never passes for this toolchain's. An override that cannot be honoured is refused before anything runs, exit 1.
