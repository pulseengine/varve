# Shared plumbing for the REQ-SYSTEST-001 system gates. Sourced, not run.
#
# The producing half every systest job shares: build varve, turn varve's OWN
# Cargo.lock into a signed layer (250 crate payloads, several names at more
# than one version), and stand up a pinned consumer project around it. The
# consuming half differs per gate (offline Cargo build, OCI registry round
# trip) and lives in the callers.

set -euo pipefail

systest_repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

# Build (or accept) the varve under test. Sets VARVE.
systest_build_varve() {
  local repo="$1"
  if [ -n "${VARVE_BIN:-}" ]; then
    VARVE="$VARVE_BIN"
  else
    (cd "$repo" && cargo build --release -p varve)
    VARVE="$repo/target/release/varve"
  fi
  "$VARVE" --version
}

# Deposit varve's own Cargo.lock as a layer and pin a project on it.
#
# On return:
#   $WORK/layout          the signed oci-layout (baseline line-status attached)
#   $WORK/root.pub        the trust root the layer verifies against
#   $WORK/project         a directory whose varve.toml pins $LAYER
#   VARVE_ROOT, VARVE_TRUST_ROOT exported for the varve invocations that follow
systest_make_layer() {
  local repo="$1" work="$2"
  LAYER="${VARVE_SYSTEST_LAYER:-2026.08.0}"
  local line="${LAYER%.*}"
  local issued_at
  issued_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Populate the real cargo cache with every .crate the lock pins. This is
  # the ONLY network step; everything downstream must hold offline.
  (cd "$repo" && cargo fetch --locked)

  python3 "$repo/tools/systest/gen-crate-deposit-spec.py" \
    --lock "$repo/Cargo.lock" \
    --cache "${CARGO_HOME:-$HOME/.cargo}/registry/cache" \
    --layer "$LAYER" --channel rolling --counter 1 \
    --out "$work/deposit-spec.toml"

  "$VARVE" keygen --out "$work/root.key" --pub "$work/root.pub"
  "$VARVE" deposit \
    --spec "$work/deposit-spec.toml" \
    --issued-at "$issued_at" \
    --key "$work/root.key" --key-id systest-root-1 \
    --out "$work/layout"

  # A baseline line-status, exactly as deposit-layer.yml attaches one: the
  # registry push recipe reads it, and `varve status` works after install.
  printf '{"line":"%s","counter":1,"issued-at":"%s"}\n' "$line" "$issued_at" \
    > "$work/baseline-status.json"
  "$VARVE" sign-status \
    --file "$work/baseline-status.json" \
    --key "$work/root.key" --key-id systest-root-1 \
    --out "$work/baseline-status.dsse.json"
  "$VARVE" attach-status --layout "$work/layout" --status "$work/baseline-status.dsse.json"

  mkdir -p "$work/project"
  printf 'manifest-version = 1\n[toolchain]\nchannel = "rolling"\nlayer = "%s"\n' \
    "$LAYER" > "$work/project/varve.toml"

  export VARVE_ROOT="$work/varve-root"
  export VARVE_TRUST_ROOT="$work/root.pub"
}
