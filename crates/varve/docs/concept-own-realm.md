# Running your own realm

An organisation with its own key, its own tools and its own layers — not a consumer of someone else's. End to end, in one transcript.

## 1. Mint a key

```sh
varve keygen --out acme.key --pub acme.pub
```

`acme.key` is 128 hex characters and secret. `acme.pub` is 64 and public — it is your realm's `trust-root`. Guard the secret half: it is the whole of your realm's authority (see `varve docs signing-keys`).

## 2. Deposit a layer under it

```sh
varve deposit \
  --layer 2026.08.0 --channel qualified --counter 1 \
  --issued-at 2026-08-01T00:00:00Z \
  --key acme.key --key-id acme-root-1 \
  --out ./layout \
  --tool "acmetool@1.0.0=./dist/acmetool"
```

Or `--spec` for anything non-trivial — see `varve docs config-reference`. varve refuses to sign a key whose halves disagree, a channel no pin can name, or a non-RFC-3339 timestamp, and re-verifies what it signed before returning.

## 3. Define the realm

`varve-realms.toml`, handed to your consumers:

```toml
[realm.acme]
registry   = "oci://ghcr.io/acme/layers"
trust-root = "c1d4e7a02b58f36c9e14d7a0b3f68c25e91a4d7b0c36f89e25a1d4b70c68f39a"
# ^ EXAMPLE ONLY — paste the 64 characters your own acme.pub holds.
```

## 4. A consumer pins it

```toml
manifest-version = 1

[toolchain]
realm   = "acme"
channel = "qualified"
layer   = "2026.08.0"
```

```sh
varve install --from ./layout    # or from the registry, once pushed
varve verify                     # against YOUR root, not PulseEngine's
varve which acmetool
```

## What you are taking on

The key is a single point of failure: varve has no key rotation, no thresholds and no revocation channel yet (`varve docs signing-keys` states this plainly). A realm is also a boundary, not a hierarchy — nothing your root signs is acceptable in another realm, and nothing another root signs is acceptable in yours. That is the property that makes composing an upstream realm safe: see `varve docs composition`.

Publishing is `varve docs deploy`.
