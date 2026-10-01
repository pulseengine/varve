#!/usr/bin/env bash
# The OCI transport system gate — REQ-SYSTEST-001 clause 2 (varve#62).
#
# A REAL registry round trip: deposit varve's own Cargo.lock as a signed
# layer, push it into a running OCI registry with a STANDARD client (oras,
# following the documented recipe in `varve docs deploy` /
# .github/workflows/deposit-layer.yml), then `varve install --from
# oci+http://…` and `varve verify` against that registry. Until this runs,
# "resolves in any OCI client" rests on annotations being spelled right
# rather than on anything executed.
#
# Registry: $REGISTRY (host:port, already running — e.g. a CI service
# container) or, when unset, a pinned zot binary is downloaded,
# checksum-verified and launched on 127.0.0.1:$REGISTRY_PORT (default 15151).
#
# Usage: tools/systest/oci-roundtrip.sh [workdir]

set -euo pipefail

WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/varve-oci.XXXXXX")}"
mkdir -p "$WORK/bin"

# shellcheck source=tools/systest/lib.sh
. "$(dirname "$0")/lib.sh"
REPO="$(systest_repo_root)"

echo "== oci-roundtrip: workdir $WORK"
systest_build_varve "$REPO"
systest_make_layer "$REPO" "$WORK"
ensure_oras
ensure_registry
echo "== registry $REGISTRY, oras $("$ORAS" version | head -1)"

# ── push the deposited layout with a STANDARD client, per `varve docs deploy` ─
LAYOUT="$WORK/layout"
REPO_REF="$REGISTRY/systest/layers"
systest_push_layout "$LAYOUT" "$REPO_REF" "$LAYER"

# A second standard client view: the tag resolves through the plain
# distribution API, not through anything varve-shaped.
curl -fsS -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  "http://$REGISTRY/v2/systest/layers/manifests/$LAYER" >/dev/null

# ── the consuming half: varve installs and verifies FROM THE REGISTRY ────────
export VARVE_ROOT="$WORK/varve-root-oci"   # fresh core: nothing local to fall back on
cd "$WORK/project"
"$VARVE" install --from "oci+http://$REGISTRY/systest/layers"
"$VARVE" verify
"$VARVE" status   # the baseline line-status must have travelled with the layer

echo "== oci-roundtrip: PASS — deposited layout pushed by oras, installed and verified from $REGISTRY"
