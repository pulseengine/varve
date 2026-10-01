#!/usr/bin/env bash
# `varve outdated` against a REAL published line index — REQ-LAYERDIFF-001
# clause 1, and the first exercise anywhere of REQ-INDEXAUTH-001's publisher.
#
# REQ-INDEXAUTH-001 has been verified, implemented and tested since 2026-09-06
# and its own notes say what was missing: "a fetch path with no publisher is a
# check that cannot fire." No realm has ever published a line index — measured
# again 2026-10-01, ghcr.io/pulseengine/layers serves 21 layer tags and zero
# `line-index-*`. So every consumer-side guarantee that rests on the index has
# been reasoning about a document that does not exist, and `varve outdated`
# could only ever answer "cannot answer".
#
# This publishes one. Two layers into a real registry through the documented
# `varve docs attach-index` recipe, a signed index naming both, a project
# pinned on the OLDER, and `varve outdated` asked what is newer.
#
# THE CONTROLS ARE THE POINT, because the failures here are all quiet:
#
#   * no index published -> "cannot answer", never "nothing newer". Collapsing
#     those two is the whole reason a tag listing is refused.
#   * an index signed by ANOTHER key -> refused. The realm root is the only key
#     an index may verify against; if a registry could sign its own listing the
#     document would be decoration.
#   * an index naming a layer the registry does NOT serve -> refused, naming it.
#     That is the hiding this requirement exists to detect (clause 3).
#
# Usage: tools/systest/line-index.sh [workdir]

set -euo pipefail

WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/varve-lineindex.XXXXXX")}"
mkdir -p "$WORK/bin" "$WORK/logs"

# shellcheck source=tools/systest/lib.sh
. "$(dirname "$0")/lib.sh"
REPO="$(systest_repo_root)"
fail() { systest_fail "$@"; }

echo "== line-index: workdir $WORK"
systest_build_varve "$REPO"
ensure_oras
ensure_registry
echo "== registry $REGISTRY, oras $("$ORAS" version | head -1)"

REPO_PATH="systest/lineindex"
REPO_REF="$REGISTRY/$REPO_PATH"
LINE=2026.10
OLD=2026.10.0
NEW=2026.10.1

# ── two layers, same realm root, deposited and pushed ───────────────────────
# One key for both, because a line index is signed by the REALM root and both
# layers must verify against it — two roots would be two realms.
# The fingerprint comes from keygen's OWN output. Computing it here (a sha256
# of the public-half file) gives a different number, and a realm pinned to a
# wrong root would make the impostor control below pass for the wrong reason.
"$VARVE" keygen --out "$WORK/root.key" --pub "$WORK/root.pub" \
  >"$WORK/logs/keygen.log" 2>&1
TRUST_ROOT_HEX="$(sed -n 's/.*trust-root = "\([0-9a-f]*\)".*/\1/p' "$WORK/logs/keygen.log")"
[ -n "$TRUST_ROOT_HEX" ] || { cat "$WORK/logs/keygen.log"; fail "could not read the trust root keygen printed"; }

make_layer() { # layer-id counter outdir
  local layer="$1" counter="$2" out="$3" issued support
  issued="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\n' "fixture payload for $layer" > "$WORK/tool-$layer"
  cat > "$WORK/spec-$layer.toml" <<SPEC
layer = "$layer"
channel = "rolling"
counter = $counter

[[tool]]
name = "fixture"
version = "1.0.$counter"
path = "$WORK/tool-$layer"
SPEC
  "$VARVE" deposit --spec "$WORK/spec-$layer.toml" --issued-at "$issued" \
    --key "$WORK/root.key" --key-id systest-root-1 --out "$out" >/dev/null
  support="$("$VARVE" support-horizon --channel rolling --issued-at "$issued")"
  printf '{"line":"%s","counter":%s,"issued-at":"%s","support-until":"%s"}\n' \
    "$LINE" "$counter" "$issued" "$support" > "$WORK/status-$layer.json"
  "$VARVE" sign-status --file "$WORK/status-$layer.json" \
    --key "$WORK/root.key" --key-id systest-root-1 \
    --out "$WORK/status-$layer.dsse.json" >/dev/null
  "$VARVE" attach-status --layout "$out" --status "$WORK/status-$layer.dsse.json" >/dev/null
}

make_layer "$OLD" 1 "$WORK/layout-old"
systest_push_layout "$WORK/layout-old" "$REPO_REF" "$OLD"
DIGEST_OLD="$SYSTEST_PAYLOAD_DIGEST"
make_layer "$NEW" 2 "$WORK/layout-new"
systest_push_layout "$WORK/layout-new" "$REPO_REF" "$NEW"
DIGEST_NEW="$SYSTEST_PAYLOAD_DIGEST"
echo "== pushed $OLD ($DIGEST_OLD) and $NEW ($DIGEST_NEW)"

# ── a realm that declares the index, and a project pinned on the OLDER ──────
mkdir -p "$WORK/project"
# TWO realms over one registry, differing only in the declaration. That
# declaration is what decides whether a MISSING index is "cannot answer" or an
# error (REQ-INDEXAUTH-001 clause 5), and both answers are correct for their
# realm — which is exactly why both are exercised here. Every realm that
# exists today is the non-declaring kind, so that is the one the main case uses.
cat > "$WORK/project/varve-realms.toml" <<REALMS
[realm.systest]
registry   = "oci+http://$REGISTRY/$REPO_PATH"
trust-root = "$TRUST_ROOT_HEX"

[realm.systest-strict]
registry     = "oci+http://$REGISTRY/$REPO_PATH"
trust-root   = "$TRUST_ROOT_HEX"
signed-index = true
REALMS

pin_realm() { # realm-name
  printf 'manifest-version = 1\n[toolchain]\nrealm = "%s"\nchannel = "rolling"\nlayer = "%s"\n' \
    "$1" "$OLD" > "$WORK/project/varve.toml"
}
pin_realm systest
export VARVE_ROOT="$WORK/varve-root"

# ── publish the signed index, per `varve docs attach-index` ─────────────────
sign_and_push_index() { # counter entries-json out-label key
  local counter="$1" entries="$2" label="$3" key="$4" doc env
  doc="$WORK/index-$label.json"
  env="$WORK/index-$label.dsse.json"
  jq -n --arg line "$LINE" --argjson counter "$counter" \
        --arg issued "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson layers "$entries" \
    '{line: $line, counter: $counter, "issued-at": $issued, layers: $layers}' > "$doc"
  "$VARVE" sign-index --file "$doc" --key "$key" --key-id systest-root-1 --out "$env" >/dev/null
  "$ORAS" blob push --plain-http "$REPO_REF" "$env" >/dev/null
  jq -n --arg d "sha256:$(systest_sha256_of "$env")" --argjson s "$(wc -c < "$env")" \
    '{
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      artifactType: "application/vnd.pulseengine.varve.line-index.v1+json",
      config: { mediaType: "application/vnd.oci.empty.v1+json",
                digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                size: 2 },
      layers: [ { mediaType: "application/json", digest: $d, size: $s,
                  annotations: {"eu.pulseengine.varve.role": "line-index"} } ]
    }' > "$WORK/index-manifest-$label.json"
  "$ORAS" manifest push --plain-http "$REPO_REF:line-index-$LINE" \
    "$WORK/index-manifest-$label.json" >/dev/null
}

BOTH="$(jq -n --arg o "$OLD" --arg od "$DIGEST_OLD" --arg n "$NEW" --arg nd "$DIGEST_NEW" \
  '[{layer:$o,digest:$od,channel:"rolling",counter:1},
    {layer:$n,digest:$nd,channel:"rolling",counter:2}]')"

# ── CONTROL 1 (before publishing): no index means "cannot answer" ──────────
# The realm does NOT declare an index, which is every real realm today. The
# answer must be "I cannot establish this", never "there is nothing newer":
# collapsing those two is the whole reason an unauthenticated listing is
# refused, and it is the one failure a consumer could not detect.
cd "$WORK/project"
pin_realm systest
"$VARVE" outdated --json >"$WORK/logs/no-index.json" 2>&1 \
  || { cat "$WORK/logs/no-index.json"; fail "outdated failed with no index published"; }
jq -e '.answerable == false and .reason == "no-signed-index"' "$WORK/logs/no-index.json" >/dev/null \
  || { cat "$WORK/logs/no-index.json"; fail "with no index published, outdated must say it cannot answer"; }
jq -e '(.newer // []) | length == 0' "$WORK/logs/no-index.json" >/dev/null \
  || fail "outdated reported layers from an index that was never published"
echo "   control 1: no index -> cannot answer, not 'nothing newer'"

# ── CONTROL 4: a realm that PROMISED an index and has none is an error ─────
# REQ-INDEXAUTH-001 clause 5/6: failing open where the realm declared one would
# let an attacker simply delete the index. This is the documented reason not to
# set `signed-index = true` before the publisher exists, and it is checked here
# so the warning is not merely prose.
pin_realm systest-strict
if "$VARVE" outdated >"$WORK/logs/strict-missing.log" 2>&1; then
  cat "$WORK/logs/strict-missing.log"
  fail "a realm declaring signed-index accepted a MISSING index"
fi
grep -q "systest-strict" "$WORK/logs/strict-missing.log" \
  || { cat "$WORK/logs/strict-missing.log"; fail "the refusal does not name the realm that promised one"; }
echo "   control 4: a realm that promised an index and has none is refused by name"
pin_realm systest

# ── the real thing ─────────────────────────────────────────────────────────
sign_and_push_index 1 "$BOTH" good "$WORK/root.key"
"$VARVE" outdated --json >"$WORK/logs/outdated.json" 2>&1 \
  || { cat "$WORK/logs/outdated.json"; fail "outdated failed against a published index"; }
cat "$WORK/logs/outdated.json"
jq -e '.answerable == true' "$WORK/logs/outdated.json" >/dev/null \
  || fail "a published, verified index must be answerable"
jq -e --arg n "$NEW" '[.newer[].layer] == [$n]' "$WORK/logs/outdated.json" >/dev/null \
  || { cat "$WORK/logs/outdated.json"; fail "expected exactly $NEW to be newer than the pinned $OLD"; }
jq -e --arg d "$DIGEST_NEW" '.newer[0].digest == $d' "$WORK/logs/outdated.json" >/dev/null \
  || fail "the reported digest is not the one the index signed"
echo "   reported $NEW as newer than the pinned $OLD, from a SIGNED index"

# Clause 4: nothing was written. The pin and the store are what a bad answer
# would have changed, so they are what gets checked.
grep -q "layer = \"$OLD\"" "$WORK/project/varve.toml" \
  || fail "outdated rewrote the pin"
test ! -d "$VARVE_ROOT" || fail "outdated created a store"
echo "   nothing written: pin unchanged, no store created"

# ── CONTROL 2: an index signed by another key is refused ───────────────────
"$VARVE" keygen --out "$WORK/impostor.key" --pub "$WORK/impostor.pub" >/dev/null
sign_and_push_index 2 "$BOTH" impostor "$WORK/impostor.key"
if "$VARVE" outdated >"$WORK/logs/impostor.log" 2>&1; then
  cat "$WORK/logs/impostor.log"
  fail "an index signed by a key that is NOT the realm root was accepted"
fi
echo "   control 2: an index signed by another key is refused"

# ── CONTROL 3: an index naming a layer the registry does not serve ─────────
# The hiding case, inverted: the index is the floor, so a layer it names and
# the registry does not is the detection clause 3 exists for.
HIDDEN="$(jq -n --arg o "$OLD" --arg od "$DIGEST_OLD" \
  '[{layer:$o,digest:$od,channel:"rolling",counter:1},
    {layer:"2026.10.9",digest:"sha256:0000000000000000000000000000000000000000000000000000000000000000",channel:"rolling",counter:9}]')"
sign_and_push_index 3 "$HIDDEN" hidden "$WORK/root.key"
if "$VARVE" outdated >"$WORK/logs/hidden.log" 2>&1; then
  cat "$WORK/logs/hidden.log"
  fail "an index naming a layer the registry does not serve was accepted"
fi
grep -q "2026.10.9" "$WORK/logs/hidden.log" \
  || { cat "$WORK/logs/hidden.log"; fail "the refusal does not name the omitted layer"; }
echo "   control 3: a layer the registry will not serve is refused BY NAME"

echo "== line-index: PASS — a published signed index, read and acted on, with four controls red"
