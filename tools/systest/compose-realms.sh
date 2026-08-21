#!/usr/bin/env bash
# TWO REALMS, COMPOSED — REQ-REALM2-001 clauses 1, 2, 3 and 4.
#
# Layer composition has always been exercised by fixtures. Every defect it has
# had — a diamond refused as a cycle, cross-realm verification that was dead
# code under test, an export that followed only the root, an install check that
# was direct-only — was found by review or by a persona, never by use. The
# topology this project exists for has never actually been run: PulseEngine
# tools that CHECK, bytecodealliance tools that BUILD, one pin over both.
#
# This gate runs it. Two realms, two independently generated trust roots, two
# layers assembled by the PRODUCTION assembler (tools/build-deposit-spec.sh —
# the same script deposit-layer.yml runs, not a copy of its logic), deposited
# and signed with `varve deposit`, installed one at a time as a consumer would,
# and verified each against ITS OWN realm's root.
#
# And they COLLIDE. `pulseengine/wasm-tools` is a fork of
# `bytecodealliance/wasm-tools` — the fork exists because upstream does not
# attest every tool — so both layers ship a tool called `wasm-tools`. That is
# not an edge case; it is what happens the day the fork is cut. Before
# v0.29.0 varve refused the composition outright and offered two fixes: one
# ("restrict the pin's `tools`") STRUCTURALLY incapable of working, because
# `tools` filtered by NAME and the collision is one name; the other ("remove the
# duplicate from one layer") unavailable to a consumer composing a realm they do
# not control. Sections 5 to 8 are the way through, and each asserts against the
# BINARY the composition dispatches, not against a path.
#
# What this gate does NOT do: publish. Pushing a realm root is a ceremony `varve
# docs root-ceremony` says should be air-gapped and unhurried, and it is
# deliberately not a condition of the requirement. The gate stops at a verified,
# composed, dispatching local core.
#
# Usage: tools/systest/compose-realms.sh [workdir]

set -euo pipefail

WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/varve-compose-realms.XXXXXX")}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

# shellcheck source=tools/systest/lib.sh
. "$(dirname "$0")/lib.sh"
REPO="$(systest_repo_root)"

FIXTURES="$REPO/tools/systest/fixtures/deposit-layer"
ASSEMBLER="$REPO/tools/build-deposit-spec.sh"
mkdir -p "$WORK/logs"

echo "== compose-realms systest: workdir $WORK"

fail() { echo "FAIL: $*" >&2; exit 1; }

# ── 0. the recorded release inventory, shared with the producer gate ─────────
systest_materialise_releases "$FIXTURES/releases.tsv" "$WORK/releases" "$WORK/.tarstage"
export VARVE_FIXTURE_RELEASES="$WORK/releases"

systest_build_varve "$REPO"
ISSUED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# A PATH with nothing of the developer's on it. `wasm-tools` and `rivet` are
# tools a PulseEngine developer has in ~/.cargo/bin, and `varve verify`
# correctly reports those as shadowed (REQ-SHADOW-001) — a true finding about
# the machine that has nothing to do with whether two realms compose.
CLEAN_PATH="$WORK/empty-bin:/usr/bin:/bin"
mkdir -p "$WORK/empty-bin"

# Run the PRODUCTION assembler against the fixture-backed `gh` and `cosign`.
# The doubles replace the SERVICE, never the component under test: every line
# of the assembler executes for real.
assemble() { # scenario-name  (env: LAYER COUNTER TARBALL_TOOLS WSC_VERSION VSIX_PACKAGES [COMPOSES])
  local name="$1"
  STAGE="$WORK/stage-$name"
  rm -rf "$STAGE"
  VARVE_FIXTURE_GH_LOG="$WORK/logs/$name.gh" \
  VARVE_FIXTURE_COSIGN_LOG="$WORK/logs/$name.cosign" \
  PATH="$FIXTURES/bin:$PATH" \
    "$ASSEMBLER" "$STAGE" >"$WORK/logs/$name.log" 2>&1 \
    || { cat "$WORK/logs/$name.log"; fail "the assembler could not build the $name layer"; }
}

# Deposit a staged spec under a realm's own key. Echoes the layer's manifest
# digest, which is the identity an `[[include]]` names.
deposit_realm() { # realm layer counter stage-name
  local realm="$1" layer="$2" counter="$3" stage="$4"
  # `keygen` refuses to overwrite a key, correctly. Re-running the gate into
  # the same workdir is an ordinary thing to do while developing it, so clear
  # the PREVIOUS run's material rather than inheriting a root nothing here
  # generated.
  rm -f "$WORK/$realm.key" "$WORK/$realm.pub"
  rm -rf "$WORK/layout-$realm"
  "$VARVE" keygen --out "$WORK/$realm.key" --pub "$WORK/$realm.pub" >/dev/null
  "$VARVE" deposit \
    --spec "$WORK/stage-$stage/deposit-spec.toml" \
    --issued-at "$ISSUED_AT" \
    --key "$WORK/$realm.key" --key-id "$realm-root-1" \
    --out "$WORK/layout-$realm" >"$WORK/logs/deposit-$realm.log" 2>&1 \
    || { cat "$WORK/logs/deposit-$realm.log"; fail "varve deposit refused the $realm layer"; }
  printf '{"line":"%s","counter":%s,"issued-at":"%s"}\n' "${layer%.*}" "$counter" "$ISSUED_AT" \
    > "$WORK/$realm-status.json"
  "$VARVE" sign-status --file "$WORK/$realm-status.json" \
    --key "$WORK/$realm.key" --key-id "$realm-root-1" \
    --out "$WORK/$realm-status.dsse.json" >/dev/null
  "$VARVE" attach-status --layout "$WORK/layout-$realm" \
    --status "$WORK/$realm-status.dsse.json" >/dev/null
  # The digest a consumer reads: the blob whose artifactType says it is a varve
  # layer manifest, hashed the way varve hashes it. Reading a copy the gate
  # kept would prove the gate wrote it, not that the deposit signed it.
  python3 - "$WORK/layout-$realm" <<'PY'
import hashlib, json, pathlib, sys
layout = pathlib.Path(sys.argv[1])
for blob in sorted((layout / "blobs" / "sha256").iterdir()):
    try:
        doc = json.loads(blob.read_text())
    except (ValueError, UnicodeDecodeError):
        continue
    if doc.get("artifactType") == "application/vnd.pulseengine.varve.layer.v1+json":
        print("sha256:" + hashlib.sha256(blob.read_bytes()).hexdigest())
        break
else:
    sys.exit("no varve layer manifest blob in the deposited layout")
PY
}

# ── 1. the UPSTREAM realm: bytecodealliance ──────────────────────────────────
# Attested, not cosign-signed; asset names by upstream's own platform tags; no
# wsc and no VS Code extensions, because those are PulseEngine repos. That last
# fact is why the assembler had to learn that an EMPTY WSC_VERSION is a legal
# answer — until then it could only build a PulseEngine-shaped layer, which
# made "a second realm is constructible" a claim nothing could execute.
echo "== realm 'bytecodealliance': assemble, deposit, sign"
LAYER=2026.08.0 COUNTER=1 \
TARBALL_TOOLS="bytecodealliance/wasm-tools:v1.257.1:wasm-tools:wasm-tools-%V-%U.tar.gz" \
WSC_VERSION="" VSIX_PACKAGES="" \
  assemble upstream
grep -qF 'name = "wasm-tools"' "$WORK/stage-upstream/deposit-spec.toml" \
  || fail "the upstream layer carries no wasm-tools"
grep -qF 'proof = "build-provenance"' "$WORK/stage-upstream/deposit-spec.toml" \
  || fail "upstream's ingestion proof is not build provenance — the realms would not differ"
UP_DIGEST="$(deposit_realm bytecodealliance 2026.08.0 1 upstream)"
echo "   bytecodealliance 2026.08.0 = $UP_DIGEST"

# ── 2. the OWN realm: pulseengine, composing upstream ────────────────────────
# The fork beside a tool nothing else provides, plus the `[[include]]` that
# makes this one composition rather than two unrelated layers. The include is
# emitted by the assembler (COMPOSES), not hand-written here: a gate that
# hand-authors the artifact under test is testing its own TOML.
echo "== realm 'pulseengine': assemble the fork + rivet, composing bytecodealliance"
LAYER=2026.09.0 COUNTER=1 \
TARBALL_TOOLS="rivet:v0.33.1 wasm-tools:v1.257.1-pulseengine.1" \
WSC_VERSION="" VSIX_PACKAGES="" \
COMPOSES="$UP_DIGEST@bytecodealliance@2026.08.0" \
  assemble own
grep -qF "digest = \"$UP_DIGEST\"" "$WORK/stage-own/deposit-spec.toml" \
  || fail "the composing spec does not name the upstream layer's manifest digest"
grep -qF 'realm = "bytecodealliance"' "$WORK/stage-own/deposit-spec.toml" \
  || fail "the include does not name the realm whose root verifies it"
grep -qF 'proof = "cosign-sums"' "$WORK/stage-own/deposit-spec.toml" \
  || fail "the fork's ingestion proof is not a cosign-signed sums file"
OWN_DIGEST="$(deposit_realm pulseengine 2026.09.0 1 own)"
echo "   pulseengine 2026.09.0 = $OWN_DIGEST"

# The composition must be INSIDE the signed payload, or it is not signed at
# all: a consumer reads the include from the manifest, never from the spec.
python3 - "$WORK/layout-pulseengine" "$UP_DIGEST" <<'PY' \
  || fail "the [[include]] did not reach the SIGNED layer manifest"
import json, pathlib, sys
layout, want = pathlib.Path(sys.argv[1]), sys.argv[2]
for blob in sorted((layout / "blobs" / "sha256").iterdir()):
    try:
        doc = json.loads(blob.read_text())
    except (ValueError, UnicodeDecodeError):
        continue
    if doc.get("artifactType") != "application/vnd.pulseengine.varve.layer.v1+json":
        continue
    for e in doc["manifests"]:
        a = e.get("annotations", {})
        if a.get("eu.pulseengine.varve.kind") == "layer" and e["digest"] == want:
            if a.get("eu.pulseengine.varve.include.realm") != "bytecodealliance":
                sys.exit(f"the include names realm {a.get('eu.pulseengine.varve.include.realm')!r}")
            print("   the include is inside the signed payload, naming realm 'bytecodealliance'")
            sys.exit(0)
    sys.exit("no `layer` entry for the upstream digest in the signed manifest")
sys.exit("no varve layer manifest blob in the layout")
PY

# ── 3. two realms, defined and installed side by side ────────────────────────
# Each realm binds a NAME to (registry, trust root); the store partitions by
# trust-root fingerprint, so the two cannot cross-talk even holding layers with
# identical names.
export VARVE_ROOT="$WORK/varve-root"
mkdir -p "$WORK/consumer"
cat > "$WORK/consumer/varve-realms.toml" <<EOF
[realm.pulseengine]
registry   = "oci://example.invalid/pulseengine"
trust-root = "$(cat "$WORK/pulseengine.pub")"

[realm.bytecodealliance]
registry   = "oci://example.invalid/bytecodealliance"
trust-root = "$(cat "$WORK/bytecodealliance.pub")"
EOF

# `install` resolves THE PROJECT'S PIN, so a composition is installed one layer
# at a time — exactly what an extender does adopting an upstream realm.
mkdir -p "$WORK/consumer/upstream" "$WORK/consumer/project"
cat > "$WORK/consumer/upstream/varve.toml" <<'EOF'
manifest-version = 1

[toolchain]
realm   = "bytecodealliance"
channel = "rolling"
layer   = "2026.08.0"
EOF
pin() { # tools-line (empty = no `tools` at all)
  {
    printf 'manifest-version = 1\n\n[toolchain]\nrealm   = "pulseengine"\nchannel = "rolling"\nlayer   = "2026.09.0"\n'
    if [ -n "${1:-}" ]; then printf 'tools   = [%s]\n' "$1"; fi
  } > "$WORK/consumer/project/varve.toml"
}
# The consumer's pin, resolving tools from BOTH realms (clause 2): `rivet` from
# pulseengine's own layer, `wasm-tools` from the bytecodealliance layer it
# composes. The qualifier is what makes that expressible at all — both layers
# provide `wasm-tools`.
pin '"bytecodealliance/wasm-tools", "rivet"'

# No VARVE_TRUST_ROOT anywhere below: when a pin names a realm, the realm is
# AUTHORITATIVE, and a gate that leaked an ambient root would be proving the
# environment works rather than the realms.
in_project() { # project-dir args...
  local dir="$1"; shift
  ( cd "$dir" && env -u VARVE_TRUST_ROOT PATH="$CLEAN_PATH" "$VARVE" "$@" )
}

echo "== install each realm's layer under its own pin"
in_project "$WORK/consumer/upstream" install --from "$WORK/layout-bytecodealliance" \
  >"$WORK/logs/install-upstream.log" 2>&1 \
  || { cat "$WORK/logs/install-upstream.log"; fail "the bytecodealliance layer would not install"; }
in_project "$WORK/consumer/project" install --from "$WORK/layout-pulseengine" \
  >"$WORK/logs/install-own.log" 2>&1 \
  || { cat "$WORK/logs/install-own.log"; fail "the composing pulseengine layer would not install"; }
grep -q "composes" "$WORK/logs/install-own.log" \
  || { cat "$WORK/logs/install-own.log"; fail "install did not report the composition"; }

# Two partitions, one per trust-root fingerprint. One would mean the realms
# share a namespace, which is the isolation this whole design rests on.
N_PART="$(find "$VARVE_ROOT/realms" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
[ "$N_PART" = "2" ] || fail "expected 2 realm partitions, found $N_PART"
echo "   two realm partitions, isolated by trust-root fingerprint"

# ── 4. verified, each against ITS OWN realm's root (clause 2) ────────────────
echo "== verify: the composition, each layer against its own realm's root"
in_project "$WORK/consumer/project" verify >"$WORK/logs/verify.log" 2>&1 \
  || { cat "$WORK/logs/verify.log"; fail "the composition did not verify"; }
grep -qF "composes 2026.08.0" "$WORK/logs/verify.log" \
  || { cat "$WORK/logs/verify.log"; fail "verify did not follow the include"; }
grep -qF "realm 'bytecodealliance'" "$WORK/logs/verify.log" \
  || { cat "$WORK/logs/verify.log"
       fail "verify did not say WHICH realm's root vouched for the included layer — \
'verified' without naming the key that verified it is the claim this project exists to refuse"; }
echo "   $(grep -F 'composes' "$WORK/logs/verify.log" | head -1)"

# ── 5. the collision, unchosen: refused, naming both realms (clause 4d) ──────
# Drop the `tools` list entirely, so the pin has chosen nothing. varve must
# refuse — and the refusal is the thing under test, not the refusing.
echo "== an unchosen collision is refused, and the refusal is USABLE"
pin ""
if in_project "$WORK/consumer/project" which wasm-tools >"$WORK/logs/unchosen.log" 2>&1; then
  cat "$WORK/logs/unchosen.log"
  fail "two realms both provide 'wasm-tools' and varve picked one — install order decided \
which binary a build runs"
fi
for needle in "realm 'pulseengine'" "realm 'bytecodealliance'" \
              'tools = ["pulseengine/wasm-tools"]' 'tools = ["bytecodealliance/wasm-tools"]'; do
  grep -qF "$needle" "$WORK/logs/unchosen.log" \
    || { cat "$WORK/logs/unchosen.log"
         fail "the refusal does not carry '$needle' — clause 4d requires it to name both \
providers WITH their realms and show the qualified form to copy"; }
done
if grep -qF "Restrict the pin's \`tools\`" "$WORK/logs/unchosen.log"; then
  cat "$WORK/logs/unchosen.log"
  fail "the refusal still offers the fix that cannot work: \`tools\` filters by NAME, and the \
collision is two layers exposing the SAME name"
fi
echo "   refused, naming both realms and a line the reader can paste"

# ── 6. the qualifier decides, and the BINARY proves it (clauses 4a, 4c) ──────
# Asserting a resolved PATH would only prove varve printed something. These
# fixture payloads are runnable and say where they came from, so the gate asks
# the process that actually got exec'd.
echo "== the pin chooses, and the bare name runs what it chose"
ran() { in_project "$WORK/consumer/project" run "$1"; }

pin '"bytecodealliance/wasm-tools", "rivet"'
OUT="$(ran wasm-tools)" || { echo "$OUT"; fail "the chosen upstream wasm-tools would not run"; }
case "$OUT" in
  *"repo=bytecodealliance/wasm-tools"*) ;;
  *) fail "the pin chose bytecodealliance and a bare \`wasm-tools\` ran: $OUT" ;;
esac

pin '"pulseengine/wasm-tools", "rivet"'
OUT="$(ran wasm-tools)" || { echo "$OUT"; fail "the chosen fork would not run"; }
case "$OUT" in
  *"repo=pulseengine/wasm-tools"*) ;;
  *) fail "the pin chose pulseengine and a bare \`wasm-tools\` ran: $OUT" ;;
esac
echo "   flipping the qualifier flips which binary a bare name execs"

# A bare name where nothing collides is untouched: the pin is a COMPATIBILITY
# surface, and every pin written before this feature must keep working.
OUT="$(ran rivet)" || { echo "$OUT"; fail "an uncollided bare name stopped working"; }
case "$OUT" in *"repo=pulseengine/rivet"*) ;; *) fail "bare \`rivet\` ran: $OUT" ;; esac

# ── 7. the unselected layer stays installed, verified, addressable (4b) ──────
# "Compare our fork against upstream" is a real workflow. Losing the other
# binary entirely would be a worse answer than the refusal this replaces.
echo "== the layer the pin did NOT choose is still there, still verified, still reachable"
pin '"bytecodealliance/wasm-tools", "rivet"'
in_project "$WORK/consumer/project" verify >"$WORK/logs/verify-chosen.log" 2>&1 \
  || { cat "$WORK/logs/verify-chosen.log"; fail "choosing one realm stopped the other verifying"; }
grep -qF "composes 2026.08.0" "$WORK/logs/verify-chosen.log" \
  || fail "the unselected layer dropped out of the verified composition"

OUT="$(in_project "$WORK/consumer/project" run pulseengine/wasm-tools)" \
  || { echo "$OUT"; fail "the UNCHOSEN fork is no longer runnable qualified"; }
case "$OUT" in *"repo=pulseengine/wasm-tools"*) ;; *) fail "qualified run reached: $OUT" ;; esac
OUT="$(in_project "$WORK/consumer/project" run bytecodealliance/wasm-tools)" \
  || { echo "$OUT"; fail "the chosen upstream is not runnable qualified"; }
case "$OUT" in *"repo=bytecodealliance/wasm-tools"*) ;; *) fail "qualified run reached: $OUT" ;; esac

# A qualified `which` must name the layer that OWNS the binary. The `layer …`
# line names the layer the PIN resolves to, which for a composed tool is the
# composing one — true, and not the answer someone comparing two forks asked
# for.
in_project "$WORK/consumer/project" which bytecodealliance/wasm-tools \
  > "$WORK/logs/which-qualified.log" 2>&1 \
  || { cat "$WORK/logs/which-qualified.log"; fail "a qualified which failed"; }
grep -qF "provided by realm 'bytecodealliance' layer 2026.08.0" "$WORK/logs/which-qualified.log" \
  || { cat "$WORK/logs/which-qualified.log"
       fail "a qualified which does not name the layer that owns the binary"; }

# …and the two are genuinely different artifacts, not one file answered twice.
FORK_PATH="$(in_project "$WORK/consumer/project" which pulseengine/wasm-tools | head -1)"
UP_PATH="$(in_project "$WORK/consumer/project" which bytecodealliance/wasm-tools | head -1)"
[ "$FORK_PATH" != "$UP_PATH" ] \
  || fail "both qualified names resolve to $FORK_PATH — the composition holds one binary, not two"
cmp -s "$FORK_PATH" "$UP_PATH" \
  && fail "the two realms' wasm-tools are byte-identical; this gate would pass on a fixture \
that cannot tell them apart"
echo "   both halves reachable, at different paths, with different bytes"

# ── 8. exactly one shim per name (clause 4c) ─────────────────────────────────
# The shim directory is a flat namespace. A qualifier is PIN syntax and must
# never become a file name.
echo "== one shim per name, whatever the pin chose"
in_project "$WORK/consumer/project" shim install >"$WORK/logs/shim.log" 2>&1 \
  || { cat "$WORK/logs/shim.log"; fail "shim install failed on a two-realm composition"; }
SHIMS="$(find "$VARVE_ROOT/shims" -mindepth 1 -maxdepth 1 | sed 's#.*/##' | sort | tr '\n' ' ')"
[ "$SHIMS" = "rivet wasm-tools " ] \
  || fail "shims are '$SHIMS', expected exactly 'rivet wasm-tools' — one per NAME"
# The shim must dispatch what the PIN chose, not what installed last.
OUT="$(PATH="$VARVE_ROOT/shims:$CLEAN_PATH" sh -c "cd '$WORK/consumer/project' && \
  env -u VARVE_TRUST_ROOT VARVE_ROOT='$VARVE_ROOT' wasm-tools")" \
  || { echo "$OUT"; fail "the shim would not dispatch"; }
case "$OUT" in
  *"repo=bytecodealliance/wasm-tools"*) ;;
  *) fail "the shim dispatched something the pin did not choose: $OUT" ;;
esac
echo "   one shim per name, dispatching the pin's choice"

# ── 9. a qualifier naming a realm that provides nothing fails CLOSED ─────────
# Silently falling back to the other realm would run bytes the pin explicitly
# did not choose — the exact substitution the qualifier exists to prevent.
echo "== a qualifier naming the wrong realm is refused, not quietly substituted"
pin '"acme/wasm-tools"'
if in_project "$WORK/consumer/project" which wasm-tools >"$WORK/logs/wrong-realm.log" 2>&1; then
  cat "$WORK/logs/wrong-realm.log"
  fail "the pin named realm 'acme', which provides nothing, and varve resolved anyway"
fi
grep -qF "acme/wasm-tools" "$WORK/logs/wrong-realm.log" \
  || { cat "$WORK/logs/wrong-realm.log"; fail "the refusal does not name the selector it refused"; }
echo "   refused, naming the selector"

# ── 10. negative control: the gate must be able to go red ────────────────────
# Sections 5 to 9 are green whenever varve behaves. They would be green just the
# same if the qualifier were being IGNORED and the fixture happened to install
# the chosen realm last — a result that fires by accident is not a result. So
# rebuild varve with the pin's choice deleted from the one place it is consulted
# and require section 6 to break.
#
# The mutation is `select_tools` ignoring `chosen`, which is exactly the
# pre-v0.29.0 behaviour: refuse every collision, with no way through.
echo "== negative control: with the pin's choice ignored, section 6 must FAIL"
MUTANT="$WORK/mutant"
rm -rf "$MUTANT"
mkdir -p "$MUTANT"
# A copy of the source, not the working tree: a control that edits the repo in
# place leaves it damaged if the run is interrupted.
tar cf - -C "$REPO" crates Cargo.toml Cargo.lock | tar xf - -C "$MUTANT"
python3 - "$MUTANT/crates/varve-core/src/compose.rs" <<'PY'
import sys

MARKER = "        let picked: Vec<&ToolProvider> = match chosen.get(tool) {"
END = "        };"
path = sys.argv[1]
lines = open(path).read().split('\n')
try:
    i = lines.index(MARKER)
    j = lines.index(END, i)
except ValueError:
    sys.exit("negative control: the selection in `select_tools` has moved or been reworded. "
             "Update this control — it is currently proving nothing.")
# Ignore the pin entirely: every provider stays in the running, so a collision
# can never be settled. Precisely the state varve was in before clause 4a.
out = lines[:i] + ["        let picked: Vec<&ToolProvider> = offers.clone();",
                   "        let _ = chosen;"] + lines[j + 1:]
open(path, 'w').write('\n'.join(out))
print("   mutation applied: select_tools ignores the pin's realm choice")
PY
( cd "$MUTANT" && CARGO_TARGET_DIR="$MUTANT/target" cargo build --release -p varve ) \
  >"$WORK/logs/mutant-build.log" 2>&1 \
  || { tail -30 "$WORK/logs/mutant-build.log"; fail "the mutant would not build"; }
MUTANT_VARVE="$MUTANT/target/release/varve"

pin '"bytecodealliance/wasm-tools", "rivet"'
if ( cd "$WORK/consumer/project" && env -u VARVE_TRUST_ROOT PATH="$CLEAN_PATH" \
       "$MUTANT_VARVE" run wasm-tools ) >"$WORK/logs/mutant-run.log" 2>&1; then
  cat "$WORK/logs/mutant-run.log"
  fail "a varve that IGNORES the pin's realm choice still ran the tool — section 6 proves \
nothing about the qualifier, and every green above it is vacuous"
fi
grep -qF "provided by more than one layer" "$WORK/logs/mutant-run.log" \
  || { cat "$WORK/logs/mutant-run.log"
       fail "the mutant failed, but not on the collision — the control is not controlling \
what it claims"; }
echo "   control failed as required: without the pin's choice the collision has no escape again"

pin '"bytecodealliance/wasm-tools", "rivet"'
echo "== compose-realms systest: PASS — two realms built from two roots by the production \
assembler, composed in a SIGNED include, installed and verified each against its own root; the \
collision they share is refused with a usable fix, settled by a realm qualifier, dispatches the \
pin's choice through exactly one shim, keeps the unchosen binary reachable, and goes red when \
the choice is ignored"
