#!/usr/bin/env bash
# The PRODUCER system gate — REQ-SYSTEST-002.
#
# varve's CONSUMER path has selfhost.sh. The producer path — the layer
# assembly in .github/workflows/deposit-layer.yml, which builds the official
# signed layer — had no test at all: the only way to exercise it was to
# dispatch it against the real GHCR registry, and on 2026-08-19 that is exactly
# how it was found to be broken. rivet and spar each appear in BOTH
# TARBALL_TOOLS and VSIX_PACKAGES (a CLI and a VS Code extension from one
# release), so `verify_release` ran twice for one repo, `gh release download`
# refused to overwrite the sums it had already fetched, and `set -e` killed the
# run before anything was published. A 17-check CI gate including a 29-minute
# mutation run could not catch it, because nothing in CI executed that
# workflow.
#
# The pre-flight that preceded that deposit is the other half of the lesson. It
# dry-ran the VSIX selection against both releases' real asset lists and got it
# right — but it STUBBED `verify_release` and `asset_sha`, so it tested
# everything except the download that broke. A harness that replaces the
# component under test with a stub is not coverage. Here, every line of
# tools/build-deposit-spec.sh executes for real; what is replaced is the
# SERVICE it talks to — GitHub's release API and cosign — by fixture-backed
# doubles that reproduce the behaviour that matters, starting with `gh release
# download`'s refusal to overwrite. Section 6 is the proof that this is not the
# stubbed dry-run again: it deletes the idempotence guard from a copy of the
# assembler and requires the gate to go red.
#
# The gate runs the assembly end to end and then STOPS BEFORE `oras push`:
# deposit, sign, attach the baseline line-status, install, verify, export.
# Publishing is not what needs testing.
#
# Usage: tools/systest/deposit-layer.sh [workdir]

set -euo pipefail

WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/varve-deposit-systest.XXXXXX")}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

# shellcheck source=tools/systest/lib.sh
. "$(dirname "$0")/lib.sh"
REPO="$(systest_repo_root)"

FIXTURES="$REPO/tools/systest/fixtures/deposit-layer"
ASSEMBLER="$REPO/tools/build-deposit-spec.sh"
WORKFLOW="$REPO/.github/workflows/deposit-layer.yml"
TAB="$(printf '\t')"
mkdir -p "$WORK/logs"

echo "== deposit-layer systest: workdir $WORK"

fail() { echo "FAIL: $*" >&2; exit 1; }

sha256_of() { # file -> bare hex
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ── materialise the recorded release inventory ───────────────────────────────
# Small stand-in bytes, real asset NAMES, real SHA256SUMS shapes, real cosign
# bundle bindings. Nothing here touches the network, and nothing here depends
# on somebody's release still existing at the version the fixture names.
write_sums() { # release-dir repo version sums-style
  local dir="$1" repo="$2" version="$3" style="$4" f base sums
  sums="$dir/SHA256SUMS.txt"
  : > "$sums"
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    base="${f##*/}"
    case "$base" in SHA256SUMS.txt|SHA256SUMS.txt.cosign.bundle) continue ;; esac
    if [ "$style" = "dotslash" ]; then
      printf '%s  ./%s\n' "$(sha256_of "$f")" "$base" >> "$sums"
    else
      printf '%s  %s\n' "$(sha256_of "$f")" "$base" >> "$sums"
    fi
  done
  # What a real sigstore bundle binds together: the signer identity, the
  # issuer, and the digest of the blob it covers.
  cat > "$dir/SHA256SUMS.txt.cosign.bundle" <<BUNDLE
repo=$repo
identity=https://github.com/$repo/.github/workflows/release.yml@refs/tags/$version
issuer=https://token.actions.githubusercontent.com
sha256=$(sha256_of "$sums")
BUNDLE
}

materialise_releases() {
  local root="$WORK/releases"
  local repo version asset shape dir body binname layout stagedir
  local owner name ver style
  rm -rf "$root" "$WORK/.tarstage"
  while IFS="$TAB" read -r repo version asset shape; do
    case "$repo" in ''|'#'*) continue ;; esac
    if [ "$repo" = '!sums-style' ]; then
      mkdir -p "$root/$version"
      printf '%s\n' "$asset" > "$root/$version.sums-style"
      continue
    fi
    dir="$root/$repo/$version"
    mkdir -p "$dir"
    # Distinct bytes per asset: two payloads that hashed alike would let a
    # per-platform mix-up pass unnoticed.
    body="varve systest fixture payload
repo=$repo release=$version asset=$asset
"
    case "$shape" in
      raw|blob)
        printf '%s' "$body" > "$dir/$asset"
        ;;
      tar:*)
        binname="$(printf '%s' "$shape" | cut -d: -f2)"
        layout="$(printf '%s' "$shape" | cut -d: -f3)"
        stagedir="$WORK/.tarstage/$repo/$version/${asset%.tar.gz}"
        rm -rf "$stagedir"; mkdir -p "$stagedir"
        if [ "$binname" = "none" ]; then
          # An upstream layout change: an archive with no binary of the
          # declared name anywhere in it.
          printf 'this release ships documentation and nothing executable\n' > "$stagedir/README.md"
        elif [ "$layout" = "nested" ]; then
          mkdir -p "$stagedir/${repo##*/}-$version/bin"
          printf '%s' "$body" > "$stagedir/${repo##*/}-$version/bin/$binname"
          chmod +x "$stagedir/${repo##*/}-$version/bin/$binname"
        else
          printf '%s' "$body" > "$stagedir/$binname"
          chmod +x "$stagedir/$binname"
        fi
        tar czf "$dir/$asset" -C "$stagedir" .
        ;;
      *) fail "fixture: unknown shape '$shape' for $repo $version $asset" ;;
    esac
  done < "$FIXTURES/releases.tsv"

  for owner in "$root"/*; do
    [ -d "$owner" ] || continue
    for name in "$owner"/*; do
      [ -d "$name" ] || continue
      style="$(cat "$name.sums-style" 2>/dev/null || echo bare)"
      for ver in "$name"/*; do
        [ -d "$ver" ] || continue
        write_sums "$ver" "${owner##*/}/${name##*/}" "${ver##*/}" "$style"
      done
    done
  done
}

materialise_releases
export VARVE_FIXTURE_RELEASES="$WORK/releases"
echo "   materialised $(find "$WORK/releases" -type f | wc -l | tr -d ' ') fixture files across \
$(find "$WORK/releases" -mindepth 3 -maxdepth 3 -type d | wc -l | tr -d ' ') releases"

# ── running the assembler ────────────────────────────────────────────────────
# PATH-prepended doubles. `gh` and `cosign` are resolved from PATH by the
# assembler, which is the seam; nothing in the code under test is aware of the
# test. The doubles REQUIRE VARVE_FIXTURE_RELEASES, so a PATH mishap that
# reached the real gh would abort loudly rather than quietly go to the network.
#
# The layer under test: both dual-listed repos, a per-platform extension, a
# portable one, a tool whose binary is named differently from its repo, raw
# per-platform binaries, and a tool missing an asset on one platform.
reset_layer_env() {
  export LAYER=2026.08.9
  export COUNTER=9
  export TARBALL_TOOLS="rivet:v0.33.1 spar:v0.36.0 loom:v1.2.0 kiln:v0.4.4:kilnd"
  export WSC_VERSION=v0.10.0
  export VSIX_PACKAGES="rivet:v0.33.1:rivet-sdlc:rivet-sdlc-%V.vsix spar:v0.36.0:spar-aadl:spar-aadl-%P-%V.vsix"
  unset VARVE_FIXTURE_COSIGN_REJECT || true
}

run_assembler() { # scenario-name [assembler-path]
  local name="$1" script="${2:-$ASSEMBLER}" rc=0
  STAGE="$WORK/stage-$name"
  LOG="$WORK/logs/$name.log"
  GH_LOG="$WORK/logs/$name.gh"
  rm -rf "$STAGE"
  : > "$GH_LOG"
  VARVE_FIXTURE_GH_LOG="$GH_LOG" \
  VARVE_FIXTURE_COSIGN_LOG="$WORK/logs/$name.cosign" \
  PATH="$FIXTURES/bin:$PATH" \
    "$script" "$STAGE" >"$LOG" 2>&1 || rc=$?
  return "$rc"
}

expect_refusal() { # scenario-name expected-message description
  local name="$1" pattern="$2" desc="$3"
  if run_assembler "$name"; then
    echo "--- $name log ---"; cat "$WORK/logs/$name.log"
    fail "$desc was ACCEPTED — the assembler built a spec it should have refused"
  fi
  if ! grep -qF "$pattern" "$WORK/logs/$name.log"; then
    echo "--- $name log ---"; cat "$WORK/logs/$name.log"
    fail "$desc was refused, but not for the modelled reason (no match for: $pattern)"
  fi
  echo "   refused as required: $desc"
}

# ── 1. the layer the workflow actually assembles ─────────────────────────────
reset_layer_env
echo "== assemble: dual-listed repos, per-platform vsix, a platform with no asset"
if ! run_assembler happy; then
  echo "--- happy log ---"; cat "$WORK/logs/happy.log"
  fail "the assembler could not build the layer it is meant to build"
fi
SPEC="$WORK/stage-happy/deposit-spec.toml"

# A repo named in both lists is fetched ONCE. With a non-idempotent
# verify_release the run does not merely repeat work, it dies (section 6) — but
# assert the count too, so a future "fix" that clobbers instead of skipping is
# caught as well.
if [ "$(sort "$WORK/logs/happy.gh" | uniq -d | wc -l | tr -d ' ')" != "0" ]; then
  echo "--- repeated gh invocations ---"; sort "$WORK/logs/happy.gh" | uniq -d
  fail "an asset was downloaded twice; the release fetches are not idempotent"
fi
for dual in rivet spar; do
  n="$(grep -c -- "--repo pulseengine/$dual -p SHA256SUMS.txt" "$WORK/logs/happy.gh" || true)"
  [ "$n" = "1" ] || fail "$dual is named in both lists: expected exactly 1 sums download, got $n"
done
echo "   dual-listed repos verified once each ($(wc -l < "$WORK/logs/happy.gh" | tr -d ' ') gh calls, \
$(wc -l < "$WORK/logs/happy.cosign" | tr -d ' ') cosign verifications)"

# The omission must be announced, not silent.
grep -qF "::notice::loom has no asset for aarch64-apple-darwin" "$WORK/logs/happy.log" \
  || fail "loom's missing aarch64-apple-darwin asset produced no notice"

# ── 2. the spec parses as TOML, and says what it should ──────────────────────
python3 -c 'import sys,tomllib; tomllib.load(open(sys.argv[1],"rb"))' "$SPEC" \
  || fail "the generated deposit spec is not valid TOML"
python3 "$REPO/tools/systest/assert-deposit-spec.py" "$SPEC"

# ── 3. `varve deposit` accepts it, and the layer installs and verifies ───────
# Everything the workflow does after the spec, minus the registry push.
systest_build_varve "$REPO"
ISSUED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
"$VARVE" keygen --out "$WORK/root.key" --pub "$WORK/root.pub"
"$VARVE" deposit \
  --spec "$SPEC" \
  --issued-at "$ISSUED_AT" \
  --key "$WORK/root.key" --key-id systest-deposit-1 \
  --out "$WORK/layer-layout"
printf '{"line":"%s","counter":%s,"issued-at":"%s"}\n' "${LAYER%.*}" "$COUNTER" "$ISSUED_AT" \
  > "$WORK/baseline-status.json"
"$VARVE" sign-status --file "$WORK/baseline-status.json" \
  --key "$WORK/root.key" --key-id systest-deposit-1 \
  --out "$WORK/baseline-status.dsse.json"
"$VARVE" attach-status --layout "$WORK/layer-layout" --status "$WORK/baseline-status.dsse.json"

mkdir -p "$WORK/project"
printf 'manifest-version = 1\n[toolchain]\nchannel = "rolling"\nlayer = "%s"\n' "$LAYER" \
  > "$WORK/project/varve.toml"
export VARVE_ROOT="$WORK/varve-root"
export VARVE_TRUST_ROOT="$WORK/root.pub"
# A PATH with nothing of the developer's on it. The layer carries `rivet`,
# `spar` and `kilnd`, which a PulseEngine developer also has in ~/.cargo/bin,
# and `varve verify` correctly reports those as shadowed (REQ-SHADOW-001). That
# is a true finding about the machine and has nothing to do with whether the
# layer assembled, so the gate must not depend on whose laptop it runs on.
CLEAN_PATH="$WORK/empty-bin:/usr/bin:/bin"
mkdir -p "$WORK/empty-bin"
( cd "$WORK/project" && PATH="$CLEAN_PATH" "$VARVE" install --from "$WORK/layer-layout" \
  && PATH="$CLEAN_PATH" "$VARVE" verify \
  && PATH="$CLEAN_PATH" "$VARVE" status )

# The per-platform clause, checked from the CONSUMER end: a host gets its own
# extension and no other. Four spar-aadl packages went in; one comes out, plus
# the portable rivet one.
( cd "$WORK/project" && PATH="$CLEAN_PATH" "$VARVE" export-vsix --out "$WORK/vsix-export" ) \
  >"$WORK/logs/export-vsix.log" 2>&1 \
  || { cat "$WORK/logs/export-vsix.log"; fail "export-vsix failed on the assembled layer"; }
N_VSIX="$(find "$WORK/vsix-export" -name '*.vsix' | wc -l | tr -d ' ')"
[ "$N_VSIX" = "2" ] || {
  find "$WORK/vsix-export" -name '*.vsix'
  fail "this host resolved $N_VSIX extensions, expected 2 (one portable + one for its own platform)"
}
find "$WORK/vsix-export" -name 'spar-aadl*' | grep -q . \
  || fail "the per-platform extension did not reach a consumer on this host"
echo "   deposited, installed, verified; this host resolved exactly its own 2 extensions"

# ── 4. the shapes that must be REFUSED ───────────────────────────────────────
# One repo at TWO versions. rivet v0.33.0 exists in the fixture COMPLETE with
# its own vsix, so the only thing that can stop this is the guard — not the
# fixture running out of assets. Otherwise one release's assets would be
# checked against the other release's sums: verification that passes while
# proving nothing.
reset_layer_env
VSIX_PACKAGES="rivet:v0.33.0:rivet-sdlc:rivet-sdlc-%V.vsix"
expect_refusal version-skew \
  "is requested at more than one version in this layer" \
  "one repo requested at two different versions"

# A per-platform template that matches nothing: upstream renamed its assets.
reset_layer_env
VSIX_PACKAGES="spar:v0.36.0:spar-aadl:spar-aadl-%P-%V.vsixx"
expect_refusal vsix-template-drift \
  "matched no vsix asset for any platform" \
  "a per-platform extension whose asset naming changed upstream"

# A portable extension that is declared and absent.
reset_layer_env
VSIX_PACKAGES="rivet:v0.33.1:rivet-sdlc:rivet-sdlc-portable-%V.vsix"
expect_refusal vsix-missing \
  "ships no rivet-sdlc-portable-0.33.1.vsix" \
  "a portable extension declared in VSIX_PACKAGES that the release does not ship"

# A tarball whose layout no longer contains the binary.
reset_layer_env
TARBALL_TOOLS="hollow:v0.1.0"
expect_refusal tarball-without-binary \
  "contains no 'hollow' binary" \
  "a release tarball carrying no binary of the declared name"

# cosign rejecting the sums must stop the deposit.
reset_layer_env
export VARVE_FIXTURE_COSIGN_REJECT=pulseengine/loom
expect_refusal cosign-reject \
  "signature verification failed" \
  "a release whose SHA256SUMS.txt does not verify against its repo's identity"
unset VARVE_FIXTURE_COSIGN_REJECT

# ── 5. the SHIPPING configuration, checked statically ────────────────────────
# Section 4 proves the guard works. This proves the layer that is actually
# about to be dispatched does not trip it: the version-skew mode is silent
# until the day someone bumps one list and not the other, and it costs nothing
# to check the real env block on every PR.
echo "== the live TARBALL_TOOLS / VSIX_PACKAGES / WSC_VERSION are consistent"
# The env block writes some values quoted and some bare; strip either. BSD and
# GNU sed both understand this form.
wf_env() { sed -n "s/^  $1: //p" "$WORKFLOW" | head -1 | sed 's/^"//; s/"$//'; }
LIVE_TARBALL="$(wf_env TARBALL_TOOLS)"
LIVE_VSIX="$(wf_env VSIX_PACKAGES)"
LIVE_WSC="$(wf_env WSC_VERSION)"
{ [ -n "$LIVE_TARBALL" ] && [ -n "$LIVE_VSIX" ] && [ -n "$LIVE_WSC" ]; } \
  || fail "could not read TARBALL_TOOLS/VSIX_PACKAGES/WSC_VERSION out of $WORKFLOW — this check \
silently stops checking if the env block is reshaped"
PINS="$WORK/live-pins.txt"
: > "$PINS"
for entry in $LIVE_TARBALL; do
  rest="${entry#*:}"
  printf '%s\t%s\n' "${entry%%:*}" "${rest%%:*}" >> "$PINS"
done
printf 'sigil\t%s\n' "$LIVE_WSC" >> "$PINS"
for entry in $LIVE_VSIX; do
  rest="${entry#*:}"
  printf '%s\t%s\n' "${entry%%:*}" "${rest%%:*}" >> "$PINS"
done
SKEW="$(sort -u "$PINS" | cut -f1 | sort | uniq -d)"
if [ -n "$SKEW" ]; then
  printf '%s\n' "$SKEW" | while IFS= read -r r; do
    [ -n "$r" ] && echo "  $r: $(grep "^$r$TAB" "$PINS" | cut -f2 | sort -u | tr '\n' ' ')"
  done
  fail "the shipping layer names a repo at two different versions — the deposit would abort at \
verify_release, and were the guard ever removed it would verify one release's assets against \
another release's sums"
fi
echo "   $(sort -u "$PINS" | wc -l | tr -d ' ') distinct repo pins, no repo at two versions"

# ── 6. negative control: the gate must be able to go red ─────────────────────
# selfhost.sh ends by proving its isolation can fail. The equivalent here is to
# reintroduce the defect this gate exists for: delete the idempotence guard
# from a COPY of the assembler and require the happy path to break, with gh's
# real refusal in the log. A gate nobody has watched fail is not a gate.
echo "== negative control: without the idempotence guard the layer must FAIL to assemble"
MUTANT="$WORK/build-deposit-spec.mutated.sh"
python3 - "$ASSEMBLER" "$MUTANT" <<'PY'
import sys

# Put verify_release back the way it was before 871cfb3: both guards gone, so
# a repo named in both lists is verified twice. Removing only the first one
# would trip the second and the run would fail for a DIFFERENT reason — a
# control that goes red for the wrong cause is not a control.
MARKERS = ('  if [ -f "$dir/.verified-$version" ]; then',
           '  if [ -f "$dir/SHA256SUMS.txt" ]; then')
lines = open(sys.argv[1]).read().split('\n')
out, i, removed = [], 0, 0
while i < len(lines):
    if lines[i] in MARKERS:
        removed += 1
        while i < len(lines) and lines[i] != '  fi':
            i += 1
        i += 1
        continue
    out.append(lines[i])
    i += 1
if removed != len(MARKERS):
    sys.exit(f"negative control: found {removed} of {len(MARKERS)} guards in the assembler. "
             "They have moved or been reworded — update this control, it is currently proving "
             "nothing.")
open(sys.argv[2], 'w').write('\n'.join(out))
PY
chmod +x "$MUTANT"
reset_layer_env
if run_assembler mutated "$MUTANT"; then
  fail "the assembler built the layer with the idempotence guard REMOVED — this gate would not \
have caught the bug it was written for, and every green result above it is vacuous"
fi
grep -qF "already exists (use \`--clobber\`" "$WORK/logs/mutated.log" \
  || { cat "$WORK/logs/mutated.log"; fail "the mutated assembler failed, but not on the duplicate \
release download — the control is not controlling what it claims"; }
echo "   control failed as required: $(grep -F 'already exists' "$WORK/logs/mutated.log" | head -1)"

echo "== deposit-layer systest: PASS — layer assembled, deposited, installed, verified and \
exported, and the gate goes red when the guard is removed"
