# Environment

Two variables, and which one wins.

```sh
VARVE_ROOT=/opt/varve        # where everything lives; default ~/.varve
VARVE_TRUST_ROOT=/path/root.pub   # a PATH to a key file, not the key itself
```

## VARVE_ROOT

The core, the shims, the anti-rollback state and the status cache all live under it:

```
$VARVE_ROOT/
  shims/                       PATH dispatchers
  env                          the sourceable PATH setup

  core/                        no realm: installed layers
  state/                       no realm: high-water marks, cached line-status

  realms/<fingerprint>/core/   under a realm: installed layers
  realms/<fingerprint>/state/  under a realm: ITS high-water marks and cache
```

A realm namespaces the **whole** effective root, not just `core/`. Looking for
`$VARVE_ROOT/state/high-water-marks.json` on a realm-pinned project finds
nothing — it is under `realms/<fingerprint>/state/`. Realms partition by trust-root fingerprint, so the same layer id under two realms is two different installs that never collide. `varve list` labels rows by realm for exactly that reason.

Set it for containers and CI, where `$HOME` is not where you want ~200 MB per layer to land.

## VARVE_TRUST_ROOT

A path to a file holding 64 hex characters. It applies **only when the pin names no realm** — a realm's `trust-root` is authoritative and this variable is ignored, including when it points at a file that does not exist. If you set it and nothing changes, check whether your pin has a `realm`.

## Precedence

1. The pin's `realm` → that realm's `trust-root`, always.
2. Otherwise `VARVE_TRUST_ROOT`.
3. Otherwise varve fails closed and tells you both options.
