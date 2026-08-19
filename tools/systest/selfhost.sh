#!/usr/bin/env bash
# varve self-hosting under test — REQ-SYSTEST-001 clause 1 (varve#74).
#
# Deposit varve's OWN Cargo.lock (250 registry packages, 14 names at more
# than one version) as kind="crate" payloads, install it, verify it, export
# it through ONE named Cargo adapter, and build the varve workspace OFFLINE
# from that export with an isolated, empty CARGO_HOME. An adapter that cannot
# build varve does not get to claim it can build anything.
#
# The isolation is the point: without the empty CARGO_HOME the offline build
# silently falls back to the developer's real cargo cache and proves nothing.
# A negative control at the end re-runs the same offline build WITHOUT the
# export wiring and requires it to FAIL — if it passes, the isolation is
# broken and every green result above it is vacuous.
#
# Usage: tools/systest/selfhost.sh <export-crates-vendor|export-cargo> [workdir]

set -euo pipefail

ADAPTER="${1:?usage: selfhost.sh <export-crates-vendor|export-cargo> [workdir]}"
case "$ADAPTER" in
  export-crates-vendor|export-cargo) ;;
  *) echo "error: unknown Cargo adapter '$ADAPTER'" >&2; exit 2 ;;
esac
WORK="${2:-$(mktemp -d "${TMPDIR:-/tmp}/varve-selfhost.XXXXXX")}"
mkdir -p "$WORK"

# shellcheck source=tools/systest/lib.sh
. "$(dirname "$0")/lib.sh"
REPO="$(systest_repo_root)"

echo "== selfhost[$ADAPTER]: workdir $WORK"
systest_build_varve "$REPO"
systest_make_layer "$REPO" "$WORK"

# ── install + verify: the layer, then its agreement with the real lockfile ──
cd "$WORK/project"
"$VARVE" install --from "$WORK/layout"
"$VARVE" verify
# The layer's crate pins and the workspace lockfile must agree package by
# package (REQ-LOCKPIN-001) — with the REAL 250-package lock, not a fixture.
"$VARVE" verify --lockfile "$REPO/Cargo.lock"

# ── export through the adapter under test ────────────────────────────────────
EXPORT_DIR="$WORK/export"
"$VARVE" "$ADAPTER" --out "$EXPORT_DIR"
"$VARVE" verify --export "$EXPORT_DIR"
test -f "$EXPORT_DIR/.cargo/config.toml" || {
  echo "error: $ADAPTER wrote no .cargo/config.toml" >&2; exit 1
}

# ── the oracle: varve's own workspace builds OFFLINE from the export ─────────
CONSUMER="$WORK/consumer"
mkdir -p "$CONSUMER"
tar -C "$REPO" \
  --exclude='./.git' --exclude='./target' --exclude='./fuzz/target' \
  -cf - . | tar -xf - -C "$CONSUMER"
# The WHOLE export, not just its config. REQ-REPRO-001 made the registry and
# vendor paths RELATIVE so a committed export survives being cloned to another
# machine; a relative path resolves against the directory holding `.cargo/`, so
# copying the config alone left it pointing at a `registry`/`vendor` that was
# never carried across. Both adapters then failed here — a cross-workstream
# regression the merge never re-ran this script to catch.
cp -R "$EXPORT_DIR/." "$CONSUMER/"
test -f "$CONSUMER/.cargo/config.toml" || {
  echo "error: the export carried no .cargo/config.toml into the consumer" >&2; exit 1
}

EMPTY_CARGO_HOME="$WORK/cargo-home-isolated"
mkdir -p "$EMPTY_CARGO_HOME"
echo "== offline workspace build via $ADAPTER (CARGO_HOME=$EMPTY_CARGO_HOME, empty)"
(cd "$CONSUMER" && CARGO_HOME="$EMPTY_CARGO_HOME" cargo build --workspace --offline --locked)
"$CONSUMER/target/debug/varve" --version

# ── negative control: the isolation itself must be able to fail ─────────────
echo "== negative control: same offline build WITHOUT the export must fail"
# Remove the whole wiring, not only the config: leaving the registry/vendor
# tree behind would let a future change satisfy the build another way and the
# control would stop controlling anything.
rm -f "$CONSUMER/.cargo/config.toml"
rm -rf "$CONSUMER/registry" "$CONSUMER/vendor" "$CONSUMER/target"
CONTROL_HOME="$WORK/cargo-home-control"
mkdir -p "$CONTROL_HOME"
if (cd "$CONSUMER" && CARGO_HOME="$CONTROL_HOME" cargo build --workspace --offline --locked) \
    >"$WORK/negative-control.log" 2>&1; then
  echo "error: the offline build succeeded with NO export wiring and an empty" >&2
  echo "CARGO_HOME — the isolation is leaking and this gate proves nothing" >&2
  exit 1
fi
echo "   control failed as required (crates unreachable without the export)"

echo "== selfhost[$ADAPTER]: PASS — varve built varve offline from its own layer"
