#!/usr/bin/env bash
# The upstream-scanner system gate — REQ-ROLLING-001.
#
# The scanner's whole job is to be trusted enough that a human reads its
# proposal instead of re-deriving it. Everything that makes that true is a
# behaviour under some condition — a repo that appears in two env lists, an
# upstream that publishes a prerelease, an upstream whose new release nothing
# vouches for — and none of those conditions occur on the day you happen to run
# it by hand. So they are recorded here and run on every change to the scanner.
#
# What is replaced is the SERVICE — GitHub's release API and attestation store,
# and cosign — by fixture-backed doubles on PATH. Every line of
# tools/scan-upstream.sh and tools/upstream-mechanism.sh executes for real. The
# lesson of REQ-SYSTEST-002 was that a harness which stubs the component under
# test proves nothing; the seam here is the same one the deposit assembler
# uses, and for the same reason.
#
# Section 8 is the negative control: it removes the property that makes the
# proposal safe — one release per repo across BOTH env lists — from a copy of
# the scanner and requires this gate to go red. A gate nobody has watched fail
# is not a gate.
#
# Usage: tools/systest/scan-upstream.sh [workdir]

set -euo pipefail

WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/varve-scan-systest.XXXXXX")}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

# shellcheck source=tools/systest/lib.sh
. "$(dirname "$0")/lib.sh"
REPO="$(systest_repo_root)"

FIXTURES="$REPO/tools/systest/fixtures/scan-upstream"
SCANNER="$REPO/tools/scan-upstream.sh"
TAB="$(printf '\t')"
mkdir -p "$WORK/logs"

echo "== scan-upstream systest: workdir $WORK"
fail() { echo "FAIL: $*" >&2; exit 1; }

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ── the recorded upstream ────────────────────────────────────────────────────
# Small stand-in bytes, real asset NAMES, real release-listing shape. Each repo
# models one condition the scanner has to get right:
#
#   alpha    moves, and is named in BOTH env lists — the bump must land in both
#            or the deposit verifies one release's assets against another's sums
#   beta     already at the newest release, with a non-default binary name
#   gamma    moves, but the release carries no attestation of any kind
#   delta    moves, and SHIPS a cosign bundle that does not verify
#   epsilon  newer versions exist but they are a prerelease and a draft
#   zeta     pinned ABOVE anything published (a withdrawn release upstream)
#   sigil    the WSC_VERSION slot, which is spelled differently from the rest
#   outside/tool  a non-pulseengine upstream, vouched by build provenance
RELEASES="$WORK/releases"
materialise() {
  rm -rf "$RELEASES"
  local repo tag state attest assets asset dir
  while IFS="$TAB" read -r repo tag state attest assets; do
    case "$repo" in ''|'#'*) continue ;; esac
    dir="$RELEASES/$repo/$tag"
    mkdir -p "$dir"
    for asset in $assets; do
      printf 'varve scan-upstream fixture\nrepo=%s tag=%s asset=%s\n' "$repo" "$tag" "$asset" > "$dir/$asset"
    done
    case "$attest" in
      cosign|cosign-tampered)
        : > "$dir/SHA256SUMS.txt"
        for asset in $assets; do
          printf '%s  %s\n' "$(sha_of "$dir/$asset")" "$asset" >> "$dir/SHA256SUMS.txt"
        done
        # What a sigstore bundle binds: the signer identity, the issuer, and
        # the digest of the blob it covers.
        {
          printf 'repo=%s\n' "$repo"
          printf 'identity=https://github.com/%s/.github/workflows/release.yml@refs/tags/%s\n' "$repo" "$tag"
          printf 'issuer=https://token.actions.githubusercontent.com\n'
          if [ "$attest" = cosign-tampered ]; then
            # The sums were edited after signing. The bundle still exists and
            # still looks right in a directory listing; it just does not cover
            # these bytes. Presence is not proof.
            printf 'sha256=%s\n' "0000000000000000000000000000000000000000000000000000000000000000"
          else
            printf 'sha256=%s\n' "$(sha_of "$dir/SHA256SUMS.txt")"
          fi
        } > "$dir/SHA256SUMS.txt.cosign.bundle"
        ;;
      provenance)
        # No sums file at all — the bytecodealliance shape. Provenance is
        # per-artifact, so the fixture records which artifacts carry one.
        for asset in $assets; do printf '%s\n' "$asset" >> "$RELEASES/$repo/.provenance"; done
        ;;
      none) ;;
      *) fail "unknown attest mode '$attest'" ;;
    esac
    printf '%s\t%s\t%s\n' "$tag" "$state" "$assets" >> "$RELEASES/$repo/.index"
  done
  # The release listing `gh api` serves, in the shape the scanner parses.
  python3 - "$RELEASES" <<'PY'
import json, os, sys
root = sys.argv[1]
for owner in sorted(os.listdir(root)):
    for name in sorted(os.listdir(os.path.join(root, owner))):
        repo = os.path.join(root, owner, name)
        index = os.path.join(repo, '.index')
        if not os.path.isfile(index):
            continue
        rels = []
        for line in open(index):
            tag, state, assets = line.rstrip('\n').split('\t')
            d = os.path.join(repo, tag)
            rels.append({
                'tag_name': tag,
                'draft': state == 'draft',
                'prerelease': state == 'pre',
                'assets': [
                    {'name': a, 'size': os.path.getsize(os.path.join(d, a))}
                    for a in sorted(os.listdir(d))
                ],
            })
        # Newest first, as the API returns it — the scanner must not depend on
        # the order.
        rels.reverse()
        json.dump(rels, open(os.path.join(repo, 'releases.json'), 'w'), indent=1)
PY
}

materialise <<FIXTURE
pulseengine/alpha	v1.0.0	ok	cosign	alpha-v1.0.0-x86_64-unknown-linux-gnu.tar.gz alpha-ext-linux-x64-1.0.0.vsix
pulseengine/alpha	v1.2.0	ok	cosign	alpha-v1.2.0-x86_64-unknown-linux-gnu.tar.gz alpha-ext-linux-x64-1.2.0.vsix
pulseengine/alpha	v1.3.0	ok	cosign	alpha-v1.3.0-x86_64-unknown-linux-gnu.tar.gz alpha-ext-linux-x64-1.3.0.vsix
pulseengine/beta	v0.5.0	ok	cosign	beta-v0.5.0-x86_64-unknown-linux-gnu.tar.gz
pulseengine/gamma	v2.0.0	ok	cosign	gamma-v2.0.0-x86_64-unknown-linux-gnu.tar.gz
pulseengine/gamma	v2.1.0	ok	none	gamma-v2.1.0-x86_64-unknown-linux-gnu.tar.gz
pulseengine/delta	v0.1.0	ok	cosign	delta-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
pulseengine/delta	v0.2.0	ok	cosign-tampered	delta-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
pulseengine/epsilon	v3.0.0	ok	cosign	epsilon-v3.0.0-x86_64-unknown-linux-gnu.tar.gz
pulseengine/epsilon	v3.1.0	pre	cosign	epsilon-v3.1.0-x86_64-unknown-linux-gnu.tar.gz
pulseengine/epsilon	v3.2.0	draft	cosign	epsilon-v3.2.0-x86_64-unknown-linux-gnu.tar.gz
pulseengine/zeta	v1.0.0	ok	cosign	zeta-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
pulseengine/sigil	v0.10.0	ok	cosign	wsc-linux-x86_64
pulseengine/sigil	v0.12.0	ok	cosign	wsc-linux-x86_64
outside/tool	v1.230.0	ok	provenance	tool-1.230.0-x86_64-linux.tar.gz
outside/tool	v1.257.1	ok	provenance	tool-1.257.1-x86_64-linux.tar.gz
FIXTURE

# ── the workflow under scan ──────────────────────────────────────────────────
# Deliberately NOT the live .github/workflows/deposit-layer.yml: this gate has
# to keep testing the same conditions after the real pins move, and it must not
# start failing merely because upstream released something.
WF="$WORK/deposit-layer.yml"
write_workflow() { # tarball wsc vsix
  cat > "$WF" <<EOF
name: Deposit layer

env:
  # A comment between the keys, as the real file has.
  TARBALL_TOOLS: "$1"
  WSC_VERSION: $2
  # And another.
  VSIX_PACKAGES: "$3"

jobs:
  deposit:
    runs-on: ubuntu-latest
EOF
}

BASE_TARBALL="alpha:v1.0.0 beta:v0.5.0:betad gamma:v2.0.0 delta:v0.1.0 epsilon:v3.0.0 zeta:v9.9.9 outside/tool:v1.230.0"
BASE_WSC="v0.10.0"
BASE_VSIX="alpha:v1.0.0:alpha-ext:alpha-ext-%P-%V.vsix"
write_workflow "$BASE_TARBALL" "$BASE_WSC" "$BASE_VSIX"

run_scan() { # name [scanner-path] [extra args...]
  local name="$1" script="${2:-$SCANNER}"; shift 2 || shift 1
  OUTDIR="$WORK/out-$name"
  LOG="$WORK/logs/$name.log"
  rm -rf "$OUTDIR"
  local rc=0
  VARVE_FIXTURE_RELEASES="$RELEASES" \
  VARVE_FIXTURE_GH_LOG="$WORK/logs/$name.gh" \
  VARVE_FIXTURE_COSIGN_LOG="$WORK/logs/$name.cosign" \
  PATH="$FIXTURES/bin:$PATH" \
    "$script" scan --workflow "$WF" --out "$OUTDIR" "$@" >"$LOG" 2>&1 || rc=$?
  return "$rc"
}

decision_of() { # outdir repo -> decision
  grep "^$2$TAB" "$1/resolved.tsv" | cut -f4 | head -1
}
target_of() { # outdir repo -> the version the proposal would pin
  grep "^$2$TAB" "$1/resolved.tsv" | cut -f3 | head -1
}
mech_of() { # outdir repo -> mechanism id
  grep "^$2$TAB" "$1/resolved.tsv" | cut -f5 | head -1
}

# ── 1. the proposal the scanner produces ─────────────────────────────────────
echo "== scan: what moved, what is held, what is silent"
run_scan happy || { cat "$WORK/logs/happy.log"; fail "the scan failed outright"; }
cat "$WORK/logs/happy.log"
OUT="$WORK/out-happy"

[ "$(cat "$OUT/status")" = moved ] || fail "status is '$(cat "$OUT/status")', expected 'moved'"

expect_decision() { # repo decision [target]
  local got; got="$(decision_of "$OUT" "$1")"
  [ "$got" = "$2" ] || fail "$1: decision '$got', expected '$2'"
  if [ $# -ge 3 ]; then
    local tgt; tgt="$(target_of "$OUT" "$1")"
    [ "$tgt" = "$3" ] || fail "$1: would pin '$tgt', expected '$3'"
  fi
  echo "   $1: $2${3:+ -> $3}"
}

expect_decision pulseengine/alpha   move    v1.3.0
expect_decision pulseengine/beta    current
expect_decision pulseengine/gamma   blocked v2.1.0
expect_decision pulseengine/delta   blocked v0.2.0
expect_decision pulseengine/sigil   move    v0.12.0
expect_decision outside/tool        move    v1.257.1

# A prerelease and a draft are not what a consumer gets by default, so they are
# not what a layer proposes.
expect_decision pulseengine/epsilon current
# Never propose a downgrade: a pin above anything published means a release was
# withdrawn upstream, which is a thing to look at, not a thing to silently undo.
expect_decision pulseengine/zeta    hold
grep -q "pin is ahead" "$OUT/resolved.tsv" || fail "zeta was held for the wrong reason"

# ── 2. the mechanism is a VALUE, not the assumption that it is cosign ────────
echo "== each move names the mechanism that vouched for it"
[ "$(mech_of "$OUT" pulseengine/alpha)" = cosign-sums ] \
  || fail "alpha should be vouched by cosign-sums, got '$(mech_of "$OUT" pulseengine/alpha)'"
[ "$(mech_of "$OUT" outside/tool)" = build-provenance ] \
  || fail "outside/tool should be vouched by build-provenance, got '$(mech_of "$OUT" outside/tool)'"
grep -q 'build-provenance' "$OUT/pr-body.md" || fail "the proposal does not report the provenance mechanism"
grep -q 'cosign-sums'   "$OUT/pr-body.md" || fail "the proposal does not report the cosign mechanism"
echo "   two mechanisms in one proposal, each named beside the tool it vouched for"

# ── 3. an unverifiable upstream blocks ITS tool, not the proposal ────────────
# Clause 5. gamma ships nothing to check; delta ships a bundle that does not
# cover its sums. Both are held; the other five still move. One unattested
# upstream must not freeze the rest of the toolchain — that is how a rolling
# channel stops rolling.
echo "== a blocked tool holds its own pin and nothing else"
PROPOSED="$OUT/deposit-layer.yml.proposed"
grep -q 'gamma:v2.0.0' "$PROPOSED" || fail "gamma was bumped despite having nothing to verify"
grep -q 'delta:v0.1.0' "$PROPOSED" || fail "delta was bumped despite a bundle that does not verify"
grep -q 'alpha:v1.3.0' "$PROPOSED" || fail "alpha did not move even though it verified"
grep -q 'WSC_VERSION: v0.12.0' "$PROPOSED" || fail "the wsc slot did not move"
grep -q "outside/tool:v1.257.1" "$PROPOSED" || fail "the provenance-backed tool did not move"
grep -q 'Held at the current pin' "$OUT/pr-body.md" || fail "the proposal does not say what was held back"
echo "   2 held, 3 moved, in one proposal"

# The tampered bundle must be REFUSED, not merely absent from the happy path:
# if the double had accepted it, delta would have been proposed and this gate
# would still have been green on a fixture that no longer modelled anything.
grep -q "verify-blob" "$WORK/logs/happy.cosign" || fail "cosign was never called — the mechanism table did not run"

# ── 4. one release per repo, across BOTH env lists ───────────────────────────
# alpha is a tool AND a VS Code extension cut from one release. The deposit
# assembler refuses a repo named at two versions, because otherwise one
# release's assets get checked against another release's sums. A proposal that
# bumped one list and not the other would be rejected at deposit time — after
# the merge, which is after the signature was authorised.
echo "== a repo in two env lists is bumped in both or in neither"
grep -q 'TARBALL_TOOLS: .*alpha:v1.3.0' "$PROPOSED" || fail "alpha not bumped in TARBALL_TOOLS"
grep -q 'VSIX_PACKAGES: .*alpha:v1.3.0:alpha-ext:' "$PROPOSED" || fail "alpha not bumped in VSIX_PACKAGES"
VER_COUNT="$(VARVE_FIXTURE_RELEASES="$RELEASES" PATH="$FIXTURES/bin:$PATH" \
             "$SCANNER" pins --workflow "$PROPOSED" | grep -c "^pulseengine/alpha$TAB")"
[ "$VER_COUNT" = 1 ] || fail "alpha resolves to $VER_COUNT versions in the proposal — the deposit would refuse it"
echo "   alpha at exactly one version across both lists"

# The entry SHAPE has to survive: the binary override and the %P/%V asset
# template encode facts about the release that no scan can rediscover.
grep -q 'beta:v0.5.0:betad' "$PROPOSED" || fail "the binary-name override was lost in the rewrite"
grep -q 'alpha-ext-%P-%V.vsix' "$PROPOSED" || fail "the vsix asset template was lost in the rewrite"
grep -q '# A comment between the keys' "$PROPOSED" || fail "the rewrite ate the surrounding file"
echo "   entry shapes and surrounding file preserved"

# ── 5. silence when nothing moved ────────────────────────────────────────────
# Clause 6. A scheduled job that reports every run is a scheduled job people
# build an inbox filter for, and then the one message that mattered lands in
# the same folder as the other ninety-nine.
echo "== nothing moved: no proposal, no PR, no notification"
write_workflow "alpha:v1.3.0 beta:v0.5.0:betad gamma:v2.1.0 delta:v0.2.0 epsilon:v3.0.0 zeta:v9.9.9 outside/tool:v1.257.1" \
               "v0.12.0" \
               "alpha:v1.3.0:alpha-ext:alpha-ext-%P-%V.vsix"
run_scan quiet || { cat "$WORK/logs/quiet.log"; fail "the no-change scan failed"; }
[ "$(cat "$WORK/out-quiet/status")" = unchanged ] \
  || fail "status is '$(cat "$WORK/out-quiet/status")', expected 'unchanged'"
[ ! -f "$WORK/out-quiet/pr-body.md" ] || fail "a PR body was written for a scan where nothing moved"
[ ! -f "$WORK/out-quiet/deposit-layer.yml.proposed" ] || fail "a proposal was written for a scan where nothing moved"
echo "   status=unchanged, no proposal on disk"

# And `propose` on that scan must be a no-op even if something calls it.
VARVE_SCAN_APPLY=1 VARVE_FIXTURE_RELEASES="$RELEASES" PATH="$FIXTURES/bin:$PATH" \
  "$SCANNER" propose --out "$WORK/out-quiet" > "$WORK/logs/quiet-propose.log" 2>&1 \
  || fail "propose failed on an unchanged scan instead of doing nothing"
grep -q "nothing to propose" "$WORK/logs/quiet-propose.log" \
  || fail "propose did something on an unchanged scan"
[ ! -f "$WORK/logs/quiet-propose.gh" ] || fail "propose contacted gh on an unchanged scan"
echo "   propose on an unchanged scan is a no-op, even with --apply"

# Everything that moved is blocked: still no proposal, because there is no diff
# to propose — and no weekly nag about an upstream that may never attest.
echo "== something moved but nothing could be vouched for"
write_workflow "alpha:v1.3.0 beta:v0.5.0:betad gamma:v2.0.0 delta:v0.1.0 epsilon:v3.0.0 zeta:v9.9.9 outside/tool:v1.257.1" \
               "v0.12.0" \
               "alpha:v1.3.0:alpha-ext:alpha-ext-%P-%V.vsix"
UPSTREAM_MECHANISMS="cosign-sums build-provenance" run_scan blocked-only || true
# gamma and delta are the only movers now, and neither verifies.
[ "$(cat "$WORK/out-blocked-only/status")" = blocked-only ] \
  || fail "status is '$(cat "$WORK/out-blocked-only/status")', expected 'blocked-only'"
[ ! -f "$WORK/out-blocked-only/pr-body.md" ] || fail "a PR was proposed with an empty diff"
echo "   status=blocked-only, no proposal"

# ── 6. the mechanism table is a table ────────────────────────────────────────
# Clause 4 must not hard-code cosign. Turning a mechanism off has to change the
# verdict for exactly the tools that depended on it, and a typo in the list must
# be an error rather than a silent "nothing is verifiable any more" — that would
# read as an upstream problem and hold the whole toolchain.
echo "== the mechanism list is configuration"
write_workflow "$BASE_TARBALL" "$BASE_WSC" "$BASE_VSIX"
UPSTREAM_MECHANISMS="cosign-sums" run_scan cosign-only \
  || { cat "$WORK/logs/cosign-only.log"; fail "the cosign-only scan failed"; }
[ "$(decision_of "$WORK/out-cosign-only" outside/tool)" = blocked ] \
  || fail "with provenance disabled, outside/tool should be blocked"
[ "$(decision_of "$WORK/out-cosign-only" pulseengine/alpha)" = move ] \
  || fail "with provenance disabled, alpha should still move"
echo "   disabling a mechanism blocks only the tools that used it"

if UPSTREAM_MECHANISMS="cosign-sums notary-v3" run_scan bad-mechanism; then
  fail "an unknown mechanism id was accepted — every tool would silently look unverifiable"
fi
grep -q "unknown mechanism" "$WORK/logs/bad-mechanism.log" \
  || { cat "$WORK/logs/bad-mechanism.log"; fail "an unknown mechanism failed for the wrong reason"; }
echo "   an unknown mechanism id is an error, not a silent block"

# ── 7. dry run is the default ────────────────────────────────────────────────
# An accidental invocation must not be able to open a pull request. The proof is
# call accounting, not the absence of a complaint: the doubles log every
# invocation, so "no PR was opened" is something this gate can see.
echo "== propose without --apply touches nothing"
rm -f "$WORK/logs/dry.gh"
VARVE_FIXTURE_RELEASES="$RELEASES" VARVE_FIXTURE_GH_LOG="$WORK/logs/dry.gh" \
PATH="$FIXTURES/bin:$PATH" \
  "$SCANNER" propose --out "$OUT" --gate pass > "$WORK/logs/dry-propose.log" 2>&1 \
  || fail "the dry run failed"
grep -q "DRY RUN" "$WORK/logs/dry-propose.log" || fail "propose did not announce a dry run"
[ ! -f "$WORK/logs/dry.gh" ] || { cat "$WORK/logs/dry.gh"; fail "the dry run called gh"; }
git -C "$REPO" diff --quiet -- .github/workflows/deposit-layer.yml \
  || fail "the dry run modified the real deposit workflow"
grep -q 'known-assemblable' "$WORK/logs/dry-propose.log" \
  || fail "the gate verdict did not reach the proposal body"
echo "   nothing called, nothing written, gate verdict carried into the body"

# ── 8. negative control: this gate must be able to go red ────────────────────
# Break the property section 4 rests on — resolve versions per LIST ENTRY
# instead of per REPO, so a repo named in both env lists is bumped in one of
# them — and require the gate to catch it. A gate nobody has watched fail is
# not a gate.
echo "== negative control: a per-list (rather than per-repo) rewrite must be caught"
# The mutant needs its sibling helper: the scanner sources the mechanism table
# from beside itself, and a copy that could not find it would "fail" for a
# reason that has nothing to do with the defect being modelled.
mkdir -p "$WORK/mutant"
cp "$REPO/tools/upstream-mechanism.sh" "$WORK/mutant/upstream-mechanism.sh"
MUTANT="$WORK/mutant/scan-upstream.mutated.sh"
python3 - "$SCANNER" "$MUTANT" <<'PY'
import sys
src = open(sys.argv[1]).read()
# Make the VSIX rewrite a no-op: exactly the mistake that would sail past a
# reviewer reading a green diff, and that the deposit would then refuse.
needle = """def bump_vsix(value):
    out = []
    for e in value.split():
        parts = e.split(':')
        if len(parts) != 4:
            sys.exit('::error::VSIX_PACKAGES entry %r is not repo:version:extension:asset-template' % e)
        parts[1] = new.get(repo_of(parts[0]), parts[1])
        out.append(':'.join(parts))
    return ' '.join(out)"""
if needle not in src:
    sys.exit("negative control is stale: bump_vsix no longer looks like this, so the "
             "mutation would not reintroduce the defect it is meant to model")
open(sys.argv[2], 'w').write(src.replace(needle, """def bump_vsix(value):
    return value"""))
PY
chmod +x "$MUTANT"
write_workflow "$BASE_TARBALL" "$BASE_WSC" "$BASE_VSIX"
run_scan mutant "$MUTANT" || { cat "$WORK/logs/mutant.log"; fail "the mutated scanner did not even run"; }
MUT_PROPOSED="$WORK/out-mutant/deposit-layer.yml.proposed"
if grep -q 'VSIX_PACKAGES: .*alpha:v1.3.0:' "$MUT_PROPOSED"; then
  fail "the mutation did not take effect — the negative control proves nothing"
fi
MUT_COUNT="$(VARVE_FIXTURE_RELEASES="$RELEASES" PATH="$FIXTURES/bin:$PATH" \
             "$SCANNER" pins --workflow "$MUT_PROPOSED" | grep -c "^pulseengine/alpha$TAB")"
[ "$MUT_COUNT" = 2 ] \
  || fail "the mutated scanner produced a consistent proposal ($MUT_COUNT version(s) for alpha) — \
section 4's check would stay green on a broken rewrite, so it is not a check"
echo "   caught: the mutated scanner pins alpha at two versions at once"

echo
echo "== scan-upstream systest PASSED (workdir $WORK)"
