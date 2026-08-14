# Recovery — repairing, removing, and going back

varve has no `uninstall`, `repair` or `gc` subcommand. That is a real gap, not a
hidden flag; the store is an ordinary directory and these are the operations it
supports.

## A layer that fails to read

A truncated or corrupted `layer.json` makes every command fail on that layer:

```
error: …/core/sha256-b449190b…/layer.json: layer.json is not a valid layer
manifest: key must be a string at line 1 column 3
```

Re-install from the same source. Anti-rollback compares counters and treats an
**equal** counter as no regression, so re-installing the layer you already have
repairs it in place:

```sh
varve install --from ./layout    # or oci://…, whatever you installed from
varve which <tool>               # confirms it reads again
```

Nothing is lost: the store is content-addressed, so the repaired layer lands
under the same digest.

## Going back to an older layer

Refused by design, and this is the anti-rollback property varve exists for:

```
error: rollback refused: layer presents counter 1 but the 2026.08 line's
high-water mark is 5 — a stale, validly-signed layer cannot be passed off as
current
```

There is no `--force`. If the newer layer is genuinely bad, the correct fix is
**forward**: the producer yanks it (`varve docs status`) and issues a higher
counter. Going backwards means editing local state by hand —

```sh
$VARVE_ROOT/state/high-water-marks.json                     # no realm in the pin
$VARVE_ROOT/realms/<fingerprint>/state/high-water-marks.json # realm-pinned
```

— which is exactly the file an attacker would edit to serve you a stale
toolchain. Do it knowingly, on a machine you control, and put it back.

## Removing a layer, and reclaiming disk

Delete its directory under `core/` (or `realms/<fingerprint>/core/`). Find it
with `varve list`, which prints each layer's digest, and match the
`sha256-<digest>` directory name. Nothing else references it. Removing a layer
does **not** lower the high-water mark, so a later install of the same layer
still works and a rollback is still refused.

## After a realm re-keys

The store partitions by trust-root fingerprint, so a new root means a new
partition: everything installed under the old key reports as not installed, and
the old partition stays on disk until you delete
`realms/<old-fingerprint>/` yourself. Budget roughly the size of a toolchain per
layer.

## Starting over

`rm -rf $VARVE_ROOT` is safe and complete — every layer is re-fetchable from its
source and re-verifiable against the pinned root. You lose the high-water marks,
which means a stale layer becomes installable again until the line's counter
catches up; on a machine that has been serving a line for a while, prefer
repairing over resetting.
