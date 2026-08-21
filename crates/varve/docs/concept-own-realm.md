# Running your own realm

An organisation with its own key, its own tools and its own layers — not a consumer of someone else's. End to end, in one transcript.

**The order matters.** Steps 1–4 are the producer side and all happen before any consumer sees anything; the install in step 6 is the LAST thing, not the next thing after `deposit`. Skipping ahead to it is the mistake this topic used to teach: re-running `deposit` into a layout you have already attached to would drop every attachment, which varve now refuses (`varve docs ci`), and a layer shipped with nothing attached can never deliver a yank.

## 1. Mint a key

```sh
varve keygen --out acme.key --pub acme.pub
```

`acme.key` is 128 hex characters and secret. `acme.pub` is 64 and public — it is your realm's `trust-root`. Guard the secret half: it is the whole of your realm's authority (see `varve docs signing-keys`).

Do this once, and do it properly: `varve docs root-ceremony` is the air-gapped generation, custody, paper-backup and storage procedure, plus what varve does not do for you afterwards — there is no rotation and no revocation, so this key is the one decision you cannot take back.

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

Use a **fresh** `--out` directory for every deposit. From here on the layout is append-only.

## 3. Sign and attach a baseline line-status

**Do not skip this, even for a first layer with nothing to say.** `deposit` attaches no line-status, and a consumer who installs a layout that carries none gets this, permanently:

```
error: no line-status document cached for line 2026.08.
```

`varve status` is where the support window, known problems and yank state live. Without a baseline in the layout there is no first document to cache, so **every consumer's `varve status` fails from the first install onward, and the day you need to yank a layer the automatic channel is not there.** The repair is not free: a consumer who already installed such a layer can be given an envelope by hand —

```sh
varve status --from-file ./status.dsse.json    # works, but you must reach them
```

— and re-pushing a layout with the baseline attached fixes *future* installs. Neither reaches the people who installed yesterday unless you can contact all of them. Attach the baseline at deposit time and you never need either.

The document, one per release LINE (`2026.08`, not `2026.08.0`):

```json
{
  "line": "2026.08",
  "counter": 1,
  "issued-at": "2026-08-01T00:00:00Z",
  "support-until": "2027-08-01",
  "yanked": {},
  "known-problems": []
}
```

```sh
varve sign-status --file status.json --key acme.key --key-id acme-root-1 \
                  --out status.dsse.json
varve attach-status --layout ./layout --status status.dsse.json
```

`attach-status` takes the SIGNED envelope, not the raw JSON. Re-sign and re-attach with a higher `counter` whenever the advisory changes — that is how a yank reaches people. Full schema: `varve docs config-reference`.

## 4. If the realm declares `signed-index = true`, sign and attach the index too

Only if. A realm that declares a signed index and ships a layout without one **fails closed** — every install of it is refused:

```
error: realm 'acme' declares that it publishes a signed line index, but none
was found for 2026.08. Either the source is not serving it, or the realm's
declaration is wrong — varve will not fall back to an unauthenticated listing
for a realm that promised one.
```

The reason to accept that cost: without an index, the list of layers a consumer resolves against is the registry's unauthenticated tag listing, and a host that simply HIDES your newest layer serves nothing that fails verification. The index is the realm's signed statement of which layers a line contains. The document's shape is in `varve docs sign-index`.

```sh
varve sign-index --file index.json --key acme.key --key-id acme-root-1 \
                 --out index.dsse.json
varve attach-index --layout ./layout --index index.dsse.json
```

Leave `signed-index` at its default `false` until the index is actually published — in the registry AND in every layout you hand out. Note that `varve archive` does not carry an index back out, so an archived layout must be re-attached (`varve docs attach-index`).

The full producer pipeline, including attestations and the constraints on ordering, is `varve docs ci`. It is the reference; this topic is the short path through it.

## 5. Define the realm

`varve-realms.toml`, handed to your consumers:

```toml
[realm.acme]
registry     = "oci://ghcr.io/acme/layers"
trust-root   = "c1d4e7a02b58f36c9e14d7a0b3f68c25e91a4d7b0c36f89e25a1d4b70c68f39a"
# ^ EXAMPLE ONLY — paste the 64 characters your own acme.pub holds.
signed-index = false     # true only once step 4 is part of every deposit
```

## 6. A consumer pins it — and installs last

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
varve status                     # the baseline from step 3 — this is the check
varve which acmetool
```

Run `varve status` yourself, from a clean core, before you hand the layout to anyone. `varve verify` passing proves the signature and the digests; it says nothing about whether the advisory channel works, and a layer that verifies perfectly and can never be yanked is exactly what steps 3–4 exist to prevent.

## What you are taking on

The key is a single point of failure: varve has no key rotation, no thresholds and no revocation channel yet (`varve docs signing-keys` states this plainly, and `varve docs root-ceremony` says what to do about it in advance). A realm is also a boundary, not a hierarchy — nothing your root signs is acceptable in another realm, and nothing another root signs is acceptable in yours. That is the property that makes composing an upstream realm safe: see `varve docs composition`.

Publishing is `varve docs deploy`.
