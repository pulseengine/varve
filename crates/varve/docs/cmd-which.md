# varve which <tool>

Prints which binary would actually run here and which layer it comes from — the resolved path plus the layer id and manifest digest. Fails closed if the pin does not resolve or the tool is absent from the layer.

The name may be **realm-qualified** — `varve which bytecodealliance/wasm-tools` — to ask about one specific provider where two realms of the composition ship the same name. A bare name answers with the one the pin chose (see `varve docs composition`).

In a MIXED toolchain (`[toolchain.override.<tool>]`, REQ-OVERRIDE-001) stdout is still the path alone — for an overridden tool, the override layer's binary — and stderr names BOTH layers: `MIXED: 'synth' is overridden — it runs from layer <override> …, not from the pinned layer <pin> …`, followed by the toolchain's identity and `VARVE_OVERRIDES` value. An override that cannot be honoured is refused here with its reason, exit 1.
