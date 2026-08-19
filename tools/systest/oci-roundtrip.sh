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

# ── pinned third-party tools (never a mutable ref) ───────────────────────────
ZOT_VERSION=v2.1.20
ZOT_SHA256_LINUX_AMD64=a32e42d042d1f17b5b1317e55cc1a415a744c873dcd05c25c56b665478258bcb
ZOT_SHA256_DARWIN_ARM64=7bdade2bfca62f5466c53dc56dd2237a56b8d321584ad5e4b87c84f8917c0a51
ORAS_VERSION=1.3.3
ORAS_SHA256_LINUX_AMD64=9ce999f8d2de03fc03968b29d743077a58783e545e5eaa53917ca177352d0e59
ORAS_SHA256_DARWIN_ARM64=f33fc12753c54172b0d0d19eaa0318d3f90fe9b094d96e8b259c881713c92e1c

sha256_check() { # file expected-hex
  local got
  if command -v sha256sum >/dev/null; then got="$(sha256sum "$1" | awk '{print $1}')"
  else got="$(shasum -a 256 "$1" | awk '{print $1}')"; fi
  if [ "$got" != "$2" ]; then
    echo "error: $1 sha256 $got != pinned $2 — refusing to run it" >&2
    return 1
  fi
}

platform_pair() { # -> linux-amd64 | darwin-arm64
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  echo linux-amd64 ;;
    Darwin-arm64)  echo darwin-arm64 ;;
    *) echo "error: no pinned zot/oras for $(uname -s)-$(uname -m)" >&2; return 1 ;;
  esac
}

ensure_oras() {
  if command -v oras >/dev/null; then ORAS="$(command -v oras)"; return; fi
  local pair asset sha
  pair="$(platform_pair)"
  asset="oras_${ORAS_VERSION}_${pair/-/_}.tar.gz"
  case "$pair" in
    linux-amd64)  sha="$ORAS_SHA256_LINUX_AMD64" ;;
    darwin-arm64) sha="$ORAS_SHA256_DARWIN_ARM64" ;;
  esac
  curl -fsSL -o "$WORK/bin/$asset" \
    "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/$asset"
  sha256_check "$WORK/bin/$asset" "$sha"
  tar -xzf "$WORK/bin/$asset" -C "$WORK/bin" oras
  ORAS="$WORK/bin/oras"
}

ensure_registry() {
  if [ -n "${REGISTRY:-}" ]; then return; fi
  local pair sha port
  pair="$(platform_pair)"
  case "$pair" in
    linux-amd64)  sha="$ZOT_SHA256_LINUX_AMD64" ;;
    darwin-arm64) sha="$ZOT_SHA256_DARWIN_ARM64" ;;
  esac
  curl -fsSL -o "$WORK/bin/zot" \
    "https://github.com/project-zot/zot/releases/download/${ZOT_VERSION}/zot-${pair}"
  sha256_check "$WORK/bin/zot" "$sha"
  chmod +x "$WORK/bin/zot"
  port="${REGISTRY_PORT:-15151}"
  cat > "$WORK/zot-config.json" <<EOF
{
  "distSpecVersion": "1.1.1",
  "storage": { "rootDirectory": "$WORK/zot-storage" },
  "http": { "address": "127.0.0.1", "port": "$port" },
  "log": { "level": "warn" }
}
EOF
  "$WORK/bin/zot" serve "$WORK/zot-config.json" >"$WORK/zot.log" 2>&1 &
  ZOT_PID=$!
  trap 'kill "$ZOT_PID" 2>/dev/null || true' EXIT
  REGISTRY="127.0.0.1:$port"
  for _ in $(seq 1 30); do
    curl -fsS "http://$REGISTRY/v2/" >/dev/null 2>&1 && return
    sleep 1
  done
  echo "error: zot did not come up on $REGISTRY; log tail:" >&2
  tail -20 "$WORK/zot.log" >&2
  exit 1
}

echo "== oci-roundtrip: workdir $WORK"
systest_build_varve "$REPO"
systest_make_layer "$REPO" "$WORK"
ensure_oras
ensure_registry
echo "== registry $REGISTRY, oras $("$ORAS" version | head -1)"

# ── push the deposited layout with a STANDARD client, per `varve docs deploy` ─
LAYOUT="$WORK/layout"
REPO_REF="$REGISTRY/systest/layers"
SIG_TYPE='application/vnd.pulseengine.varve.signature.v1+json'
STATUS_TYPE='application/vnd.pulseengine.varve.line-status.v1+json'

PAYLOAD_DIGEST=$(jq -r --arg t "$SIG_TYPE" --arg s "$STATUS_TYPE" \
  '[.manifests[] | select(.artifactType != $t and .artifactType != $s)][0].digest' "$LAYOUT/index.json")
ENVELOPE_DIGEST=$(jq -r --arg t "$SIG_TYPE" \
  '[.manifests[] | select(.artifactType == $t)][0].digest' "$LAYOUT/index.json")
STATUS_DIGEST=$(jq -r --arg s "$STATUS_TYPE" \
  '[.manifests[] | select(.artifactType == $s)][0].digest // empty' "$LAYOUT/index.json")
test -n "$STATUS_DIGEST" || { echo "error: baseline line-status missing from layout" >&2; exit 1; }
blob() { echo "$LAYOUT/blobs/sha256/${1#sha256:}"; }

printf '{}' > "$WORK/empty-config.json"
"$ORAS" blob push --plain-http "$REPO_REF" "$WORK/empty-config.json"
"$ORAS" blob push --plain-http "$REPO_REF" "$(blob "$ENVELOPE_DIGEST")"
"$ORAS" blob push --plain-http "$REPO_REF" "$(blob "$PAYLOAD_DIGEST")"
COUNT=0
for digest in $(jq -r '.manifests[].digest' "$(blob "$PAYLOAD_DIGEST")"); do
  "$ORAS" blob push --plain-http "$REPO_REF" "$(blob "$digest")" >/dev/null
  COUNT=$((COUNT + 1))
done
echo "== pushed $COUNT payload blobs"
"$ORAS" blob push --plain-http "$REPO_REF" "$(blob "$STATUS_DIGEST")"

jq -n \
  --arg env_digest "$ENVELOPE_DIGEST" \
  --argjson env_size "$(wc -c < "$(blob "$ENVELOPE_DIGEST")")" \
  --arg payload_digest "$PAYLOAD_DIGEST" \
  --argjson payload_size "$(wc -c < "$(blob "$PAYLOAD_DIGEST")")" \
  --arg status_digest "$STATUS_DIGEST" \
  --argjson status_size "$(wc -c < "$(blob "$STATUS_DIGEST")")" \
  --slurpfile payload "$(blob "$PAYLOAD_DIGEST")" \
  '{
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    artifactType: "application/vnd.pulseengine.varve.layer.v1+json",
    config: { mediaType: "application/vnd.oci.empty.v1+json",
              digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
              size: 2 },
    layers: ([
      { mediaType: "application/json", digest: $env_digest, size: $env_size,
        annotations: {"eu.pulseengine.varve.role": "envelope"} },
      { mediaType: "application/vnd.oci.image.index.v1+json", digest: $payload_digest, size: $payload_size,
        annotations: {"eu.pulseengine.varve.role": "payload"} },
      { mediaType: "application/json", digest: $status_digest, size: $status_size,
        annotations: {"eu.pulseengine.varve.role": "line-status"} }
    ] + [ $payload[0].manifests[] |
          { mediaType: "application/octet-stream", digest: .digest, size: .size } ])
  }' > "$WORK/artifact-manifest.json"
"$ORAS" manifest push --plain-http "$REPO_REF:$LAYER" "$WORK/artifact-manifest.json"

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
