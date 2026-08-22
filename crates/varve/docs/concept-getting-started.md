# Getting started

Five minutes, from nothing to a dispatched tool. Every file here is literal — copy it.

## 1. Pin a layer

`varve.toml`, committed next to your `rust-toolchain.toml`:

```toml
manifest-version = 1

[toolchain]
realm   = "pulseengine"
channel = "rolling"
layer   = "2026.08.2"
```

`manifest-version = 1` is required. `layer` is always three parts (`YYYY.MM.P`). See `varve docs pins` for `digest` and `tools`.

## 2. Name the trust root

`varve-realms.toml`, alongside it. This says where bytes come from and which key makes them acceptable:

```toml
[realm.pulseengine]
registry   = "oci://ghcr.io/pulseengine/varve/layers"
trust-root = "4e771dc62a08be89e3450f8cd807da58ff70af4a4e124ebf2d2b71684cfd9973"
```

The canonical file ships as a release asset:

```sh
curl -LO https://github.com/pulseengine/varve/releases/latest/download/varve-realms.toml
```

This is the one file you must obtain through a channel you already trust; everything after it is verified against it. See `varve docs realms`.

## 3. Install, shim, run

```sh
varve install          # fetch, verify against the realm's root, lay down
varve shim install     # PATH dispatchers; then: . "$HOME/.varve/env"
rivet --version        # dispatched from the pinned layer
```

## 4. Check what you got

```sh
varve which rivet      # which binary runs here, and from which layer
varve verify           # re-run the install-time verdict, offline
varve list             # every layer installed; realm rows labelled by fingerprint
varve status           # support window, yanks, known problems
```

## When it fails

varve fails closed and the error carries its fix. A pin that does not resolve exactly is an error, never a fallback — that is the whole point. If `install` refuses on a channel or a rollback counter, it is doing its job; read the message before working around it.

## Next

- `varve docs config-reference` — every file and every field
- `varve docs own-realm` — run your own trust universe rather than consuming this one
- `varve docs air-gap` — no network, ever

> `varve status` exits 1 with `no line-status document cached for line …` when
> the layout you installed from carries no signed advisory baseline. That is a
> missing document, not a problem with your layer; `varve verify` is the
> integrity check.
