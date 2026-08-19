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

Re-install from the same source. Anti-rollback treats an **equal** counter as no
regression, so re-installing repairs in place:

```sh
varve install --from ./layout    # or oci://…, whatever you installed from
varve which <tool>               # confirms it reads again
```

Nothing is lost: the store is content-addressed, so the repaired layer lands
under the same digest.

### …unless a higher counter in the same line was ever installed

Then the repair above **does not work**, and this is the case the section above
used to promise away. "Equal counter" is compared against the *line's high-water
mark*, not against the copy on disk. Once 2026.12.5 has been installed the line
is at 5, and the damaged 2026.12.0 is a rollback:

```
$ varve install --from ./layout-2026.12.0
error: rollback refused: layer presents counter 1 but the 2026.12 line's
high-water mark is 5 — a stale, validly-signed layer cannot be passed off as current
```

Three things follow, all observed:

- **Deleting the layer directory does not help.** The mark lives in
  `state/high-water-marks.json` and outlives the layer, deliberately — that is
  what stops an attacker from clearing the way for a stale layer by deleting one.
- **The damaged layer stays executable.** `verify` reports the tampered payload
  (`does not match its signed digest … its bytes were altered`, exit 1), but
  `varve run -- <tool>` runs it and `varve which <tool>` prints its path and
  layer id, exit 0. Dispatch does not re-verify. A broken layer you cannot
  repair is not a quiescent layer.
- **`verify` alone will not tell you.** It checks the *pinned* layer; move the
  pin to the head of the line and it exits 0 with the damaged older layer still
  on disk and still dispatchable by `varve run --varve <layer>`. Use
  `verify --all`.

The real recovery, in order of preference:

1. **Go forward.** Move the pin to the line's newest layer and re-install. This
   is the only fix that needs no hand-edited state — and if you were on the older
   layer for a reason, that reason is a producer-side yank, not a local repair
   (`varve docs status`).
2. **If you must stay on the older layer**, delete its directory *and* lower the
   mark by hand, then re-install and **put the mark back**:

   ```sh
   rm -rf "$VARVE_ROOT/core/sha256-<digest>"
   # edit state/high-water-marks.json: "2026.12": 5  ->  1
   varve install --from ./layout-2026.12.0
   varve verify
   # then restore "2026.12": 5
   ```

   Lowering the mark is exactly the edit an attacker would make, and it does not
   restore itself: after the install above the file still reads `1`, so the
   rollback window stays open until you close it. Do this on a machine you
   control and finish the job.
3. **`rm -rf $VARVE_ROOT`** and install the head of the line — see "Starting
   over" below for what that costs.

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
`sha256-<digest>` directory name. Nothing else references it.

Removing a layer does **not** lower the high-water mark. So re-installing it
later works only if it is still at or above its line's mark; if the line has
moved past it, that install is refused as a rollback exactly like any other —
see "…unless a higher counter in the same line was ever installed" above. Delete
a below-the-mark layer only when you are content never to have it back without
hand-editing state.

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
