# varve run [--varve <layer>] -- <tool> <args>

Dispatches a tool from the pinned layer with the layer identity in the environment (VARVE_LAYER, VARVE_LAYER_MANIFEST_DIGEST) so provenance tooling records which qualified set produced the output. --varve runs another installed layer without touching the pin.
