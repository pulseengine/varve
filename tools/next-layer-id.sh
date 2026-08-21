#!/usr/bin/env bash
# What is the next layer to deposit? — the merge half of REQ-ROLLING-001.
#
# When a scan proposal is MERGED, the signed deposit runs. The deposit workflow
# takes the layer identifier and the monotonic per-line counter as dispatch
# inputs, which a human typed for the four layers published so far. Typing them
# is toil; choosing them is not judgement, because the published record already
# determines the answer — and getting them wrong is unrecoverable, since varve
# has neither revocation nor rotation and a layer id, once published, is spent.
#
# So this reads the answer out of the registry instead of guessing it:
#
#   layer   = <line>.<P>   where line is the current UTC YYYY.MM and P is one
#                          past the highest P already published on that line
#                          (0 when the line is new).
#   counter = one past the counter in the highest published layer's baseline
#             line-status on that line (1 when the line is new). Counters are
#             per line and must only ever increase — an anti-rollback record
#             that went backwards would let an old layer masquerade as current.
#
# It is deliberately fail-loud. If the registry cannot be read, or the computed
# tag already exists, it refuses rather than proposing an id that would collide
# with a published layer.
#
# Usage:  tools/next-layer-id.sh [registry-ref]
# Prints: "<layer>\t<counter>"  (and a human-readable trace on stderr)
#
# Reads the registry anonymously — layer publication is public and the whole
# point of the record is that anyone can check it. A token is used if
# GH_TOKEN/GITHUB_TOKEN is set, which is what makes this work for a private
# realm too.

set -euo pipefail

REF="${1:-${VARVE_REGISTRY_REF:-ghcr.io/pulseengine/varve/layers}}"
HOST="${REF%%/*}"
REPO="${REF#*/}"
LINE="${VARVE_LAYER_LINE:-$(date -u +%Y.%m)}"

die() { echo "::error::$*" >&2; exit 1; }
note() { echo "   $*" >&2; }

# ── an anonymous pull token, or the caller's ─────────────────────────────────
scope="repository:$REPO:pull"
if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
  TOKEN="$(printf '%s' "${GH_TOKEN:-$GITHUB_TOKEN}" | base64 | tr -d '\n')"
else
  TOKEN="$(curl -fsS "https://$HOST/token?scope=$(printf '%s' "$scope" | sed 's|:|%3A|g; s|/|%2F|g')&service=$HOST" \
           | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)" \
    || die "could not obtain a pull token for $REF"
fi
AUTH="Authorization: Bearer $TOKEN"

TAGS="$(curl -fsS -H "$AUTH" "https://$HOST/v2/$REPO/tags/list" \
        | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin).get("tags") or []))' 2>/dev/null)" \
  || die "could not list tags of $REF — refusing to guess a layer id"
note "$(printf '%s\n' "$TAGS" | grep -c . || true) tag(s) published on $REF"

# ── the highest layer already on this line ───────────────────────────────────
HIGHEST=""; HIGHEST_P=-1
while IFS= read -r tag; do
  case "$tag" in
    "$LINE".*) ;;
    *) continue ;;
  esac
  p="${tag##*.}"
  case "$p" in ''|*[!0-9]*) continue ;; esac
  if [ "$((10#$p))" -gt "$HIGHEST_P" ]; then HIGHEST_P=$((10#$p)); HIGHEST="$tag"; fi
done <<EOF
$TAGS
EOF

NEXT_P=$((HIGHEST_P + 1))
LAYER="$LINE.$NEXT_P"
printf '%s\n' "$TAGS" | grep -qx "$LAYER" \
  && die "$LAYER is already published — the registry and this calculation disagree, which \
means the record moved under us; refusing to dispatch a deposit that would overwrite a layer"

# ── the counter, from the published baseline line-status ─────────────────────
# Not derived from P: `varve sign-status` advisories issued between deposits
# also advance the line counter, and a deposit that reused one of those numbers
# would break the per-line anti-rollback ordering that is varve's whole point.
if [ -z "$HIGHEST" ]; then
  COUNTER=1
  note "line $LINE is new — layer $LAYER, counter $COUNTER"
else
  STATUS_TYPE='application/vnd.pulseengine.varve.line-status.v1+json'
  MAN="$(curl -fsS -H "$AUTH" -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
         "https://$HOST/v2/$REPO/manifests/$HIGHEST")" \
    || die "could not fetch the manifest of $HIGHEST"
  DIGEST="$(printf '%s' "$MAN" | python3 -c '
import json,sys
m = json.load(sys.stdin)
for l in m.get("layers", []):
    if (l.get("annotations") or {}).get("eu.pulseengine.varve.role") == "line-status":
        print(l["digest"]); break
')"
  [ -n "$DIGEST" ] || die "$HIGHEST carries no baseline line-status — cannot establish the \
current counter for line $LINE without inventing one"
  COUNTER="$(curl -fsSL -H "$AUTH" "https://$HOST/v2/$REPO/blobs/$DIGEST" | python3 -c '
import base64,json,sys
env = json.load(sys.stdin)
print(json.loads(base64.b64decode(env["payload"]))["counter"])
')"
  case "$COUNTER" in ''|*[!0-9]*) die "unreadable counter in $HIGHEST baseline line-status" ;; esac
  note "$HIGHEST carries counter $COUNTER on line $LINE"
  COUNTER=$((COUNTER + 1))
  note "next: layer $LAYER, counter $COUNTER"
fi

printf '%s\t%s\n' "$LAYER" "$COUNTER"
