# varve which <tool>

Prints which binary would actually run here and which layer it comes from — the resolved path plus the layer id and manifest digest. Fails closed if the pin does not resolve or the tool is absent from the layer.

The name may be **realm-qualified** — `varve which bytecodealliance/wasm-tools` — to ask about one specific provider where two realms of the composition ship the same name. A bare name answers with the one the pin chose (see `varve docs composition`).
