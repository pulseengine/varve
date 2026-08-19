# Environment

Every variable varve reads, and which one wins.

| Variable | Read by | Default |
|---|---|---|
| `VARVE_ROOT` | everything | `~/.varve` |
| `VARVE_TRUST_ROOT` | verification, when the pin names no realm | none — fails closed |
| `VARVE_REGISTRY_AUTH` | `oci://` pulls against a private registry | none |
| `VARVE_UPDATE_API` | `varve self-update` only | the GitHub releases API |
| `VARVE_INSTALL_DIR`, `VARVE_VERSION`, `VARVE_ALLOW_ROOT` | `install.sh` only, never the binary | `~/.varve/bin`, `latest`, refuse |

`varve run` and the shims additionally *export* `VARVE_LAYER` and
`VARVE_LAYER_MANIFEST_DIGEST` into the dispatched tool — provenance handed
downward, not configuration read upward (`varve docs run`).

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
nothing — it is under `realms/<fingerprint>/state/`. Realms partition by
trust-root fingerprint, so the same layer id under two realms is two different
installs that never collide.

`varve list` shows that partitioning, but it labels rows by **trust-root
fingerprint**, not by realm — it prints a realm *name* only when a
`varve-realms.toml` in scope maps that fingerprint back to a name, and rows in
the top-level (no-realm) core carry no label at all:

```
2026.09.0  qualified  sha256:dec017ff…                        # top-level core, unlabelled
2026.09.0  qualified  sha256:dec017ff…  realm=acme            # run where varve-realms.toml defines acme
2026.09.0  qualified  sha256:dec017ff…  realm=1617a95ea328ba54 # run anywhere else: the raw fingerprint
```

Set `VARVE_ROOT` for containers and CI, where `$HOME` is not where you want ~200 MB per layer to land.

## VARVE_TRUST_ROOT

A path to a file holding 64 hex characters — a path, not the key itself. It
applies **only when the pin names no realm**: a realm's `trust-root` is
authoritative and this variable is ignored, including when it points at a file
that does not exist. If you set it and nothing changes, check whether your pin
has a `realm`.

## VARVE_REGISTRY_AUTH

`username:password` for the registry named in an `oci://` reference, sent as
HTTP Basic to the **token endpoint only** — never to the registry API, and never
across a redirect. A trailing newline is trimmed, so
`"AWS:$(aws ecr get-login-password …)"` works as written.

Credential precedence, first usable match wins:

1. `$VARVE_REGISTRY_AUTH`
2. `$DOCKER_CONFIG/config.json`
3. `~/.docker/config.json`
4. `$XDG_RUNTIME_DIR/containers/auth.json` (podman)

Each file is read for its `auths` object only. varve does **not** execute
`credsStore` / `credHelpers` helpers — sourcing a secret by exec'ing a
PATH-resolved binary is the class of trust REQ-SHADOW-001 exists because PATH
does not deserve. That is why ECR/GAR/ACR need the credential handed over
directly, and it is the accepted price of running no external binary.

This variable governs **transport, not acceptance**. A pull it authorises is
still refused unless the signature verifies against the pinned root.

## VARVE_UPDATE_API

Overrides the release-metadata endpoint `varve self-update` queries, for mirrors
and tests. It decides *availability* only: the candidate binary is still
accepted or refused by the signed sums against the pinned root, so pointing this
at a hostile server gets you a failed update, not a bad one.

## install.sh only

`VARVE_INSTALL_DIR`, `VARVE_VERSION` and `VARVE_ALLOW_ROOT` are read by the
bootstrap shell script, not by the `varve` binary — setting them changes nothing
about an installed varve. `install.sh` refuses to run as root unless
`VARVE_ALLOW_ROOT=1`.

## Precedence

For the trust root, which is the only place two sources compete:

1. The pin's `realm` → that realm's `trust-root`, always.
2. Otherwise `VARVE_TRUST_ROOT`.
3. Otherwise varve fails closed and tells you both options.
