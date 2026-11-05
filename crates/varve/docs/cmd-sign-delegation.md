# varve sign-delegation (offline)

Signs a realm's DELEGATION with the realm root key. In a realm that declares
`key-roles = true` the root signs nothing else: it names the keys that may sign
for each role, and those keys sign everything a consumer verifies.

| Role | Signs | Command |
|------|-------|---------|
| ROOT (offline) | the delegation | `sign-delegation` |
| LAYER (the depositor's) | layer manifests, attestations, release sums | `deposit`, `sign-attestation`, `sign-sums` |
| STATUS (a human merge's) | line-status incl. advisories, line-index | `sign-status`, `sign-index` |

The input names the root and each role's keys. `keyid` is a hint a producer
reads to default its `--key-id`; it is never used to choose a key when
verifying.

```sh
cat > delegation.json <<'JSON'
{
  "realm-root": "<hex of the root public key>",
  "counter": 1,
  "issued-at": "2026-11-05T00:00:00Z",
  "roles": {
    "layer":  { "threshold": 1, "keys": [{ "key": "<hex>", "keyid": "layer-1" }] },
    "status": { "threshold": 1, "keys": [{ "key": "<hex>", "keyid": "status-1" }] }
  }
}
JSON

varve sign-delegation --file delegation.json \
                      --key root.key \
                      --out delegation.dsse.json
# signed delegation #1 (2026-11-05T00:00:00Z) -> delegation.dsse.json
```

Point the realm at it (`varve docs config-reference`):

```text
[realm.example]
key-roles = true
delegation-file = "trust-roots/example.delegation.dsse"
```

The signing key's public half must be the document's `realm-root`, and the
result is read back through the check a consumer runs: a delegation that would
be refused is not written. The root never lists itself as a role key, and one
key serves one role.

The signing commands take `--delegation FILE` and then refuse, before signing,
a key not delegated to the command's role, including the root itself ("in a
roles realm the root signs only delegations"). A roles realm's deposit
publishes no baseline line-status: `attach-status --delegation` is refused,
because the status role is not the depositor's. Without `--delegation` every
command signs exactly as before, which is right for a realm declaring no roles.
