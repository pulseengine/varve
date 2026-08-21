#!/usr/bin/env bash
# Build the deposit spec for a varve layer — the PRODUCER half of the #157
# architecture (REQ-DEPOSIT-001), extracted from .github/workflows/deposit-layer.yml
# so that it can be EXECUTED BY A TEST (REQ-SYSTEST-002).
#
# It lived as one long inline `run:` block, which meant the only way to
# exercise it was to dispatch the real workflow against the real registry. The
# 2026.08.3 deposit died there on a bug a copy-of-the-logic test could never
# have found, so the logic now lives in one place that both the workflow and
# `tools/systest/deposit-layer.sh` invoke. A test of a copy is a test of the
# copy.
#
# What it does: download the pinned per-tool releases, establish for each one
# WHAT VOUCHED for its bytes, and emit a `varve deposit` spec naming every
# payload it staged and the mechanism that vouched for it. It does NOT deposit,
# sign or publish — the workflow's later steps do that, and the system gate
# deliberately stops before the push.
#
# Ingestion proof (REQ-INGEST-001). Two mechanisms are accepted, and the one
# that applied is RECORDED per payload so it lands inside the signed layer:
#
#   cosign-sums       a SHA256SUMS.txt verified by `cosign verify-blob` against
#                     the repo's release-workflow identity. Every PulseEngine
#                     repo publishes one.
#   build-provenance  a GitHub build attestation (`gh attestation verify`).
#                     STRONGER than a sums file: a sums file says "these bytes
#                     hash to this", an attestation binds the artifact to the
#                     workflow, repository and source commit that produced it.
#                     Its in-toto statement carries the sha256 of every asset in
#                     the release, so it replaces the sums file rather than
#                     merely accompanying it. This is how a second realm becomes
#                     ingestible at all: bytecodealliance/wasm-tools v1.257.1
#                     publishes no sums and no cosign bundle, and is attested.
#
# A release with NEITHER is REFUSED. It can be ingested only through an
# explicit, reasoned opt-in (UNVERIFIED_INGEST below) which stamps
# proof = "unverified" and the operator's reason into the signed layer.
#
# The mechanisms are tried in that order and the ladder does NOT downgrade: a
# repo that publishes sums whose signature does not verify aborts the run. "No
# cosign proof" and "a bad cosign proof" are different facts, and treating the
# second as the first would turn a detected attack into a quiet fallback.
#
# Usage:  tools/build-deposit-spec.sh <workdir>
#
# Inputs (environment — the workflow's `env:` block is where the layer's
# CONTENTS are bumped in a reviewed diff, so they are not defaulted here):
#   LAYER          layer identifier, e.g. 2026.08.4
#   COUNTER        monotonic per-line release counter
#   TARBALL_TOOLS  "[owner/]tool:version[:binary[:asset-template]] ..."
#                  owner defaults to `pulseengine`, binary to the tool name, and
#                  the template to "<tool>-<version>-%T.tar.gz". In a template,
#                  %V is the bare version, %T the Rust target triple and %U the
#                  short upstream platform tag (bytecodealliance's naming).
#   WSC_VERSION    sigil release carrying the raw per-platform wsc binaries
#   VSIX_PACKAGES  "repo:version:extension:asset-template ..."  (%V bare version,
#                  %P VS Code platform tag; no %P = one portable package)
#   PLATFORMS      optional override of the target triples to include
#   UNVERIFIED_INGEST  one "owner/repo=reason" opt-in PER LINE, for releases
#                  that offer neither mechanism. The reason is MANDATORY and is
#                  signed into the layer — see REQ-INGEST-001 clause 3. Lines,
#                  not a punctuation-separated list: the reason is prose an
#                  operator writes, and any separator that can occur inside it
#                  truncates it silently at exactly the moment it matters.
#
# Outputs, all under <workdir> so the whole staging area is one removable tree:
#   deposit-spec.toml   the spec; payload `path`s are RELATIVE to it, which is
#                       how varve resolves them (deposit.rs: SpecTool::path)
#   tools/  vsix/       the staged payload bytes the spec points at
#   downloads/ extract/ what was fetched and unpacked to produce them
#
# External programs: `gh` (release downloads and build-provenance verification)
# and `cosign` (signature verification) are taken from PATH, deliberately —
# that is the seam the system test replaces with fixture-backed doubles to stay
# hermetic. Everything else here is the real code path. `python3` is used only
# to read `gh`'s JSON; it is preinstalled on every GitHub runner.

set -euo pipefail

WORK="${1:?usage: build-deposit-spec.sh <workdir>}"
: "${LAYER:?LAYER must be set (layer identifier, e.g. 2026.08.4)}"
: "${COUNTER:?COUNTER must be set (monotonic per-line release counter)}"
: "${TARBALL_TOOLS:?TARBALL_TOOLS must be set}"
: "${WSC_VERSION:?WSC_VERSION must be set}"
: "${VSIX_PACKAGES:?VSIX_PACKAGES must be set}"

PLATFORMS="${PLATFORMS:-aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu}"

mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
cd "$WORK"
mkdir -p tools vsix downloads extract

# sha256sum is coreutils; macOS ships shasum. The workflow only ever runs on
# ubuntu, but a gate you cannot run on your own machine is a gate you will not
# run before pushing.
sha256sum_c() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -c -; else shasum -a 256 -c -; fi
}

# A TOML basic string. The recorded opt-in reason is operator text and lands
# inside a signature, so it is escaped rather than trusted to be tame.
toml_str() { printf '%s' "$1" | sed 's#\\#\\\\#g; s#"#\\"#g'; }

# The assets a release publishes, one per line. Asking WHAT IS THERE, rather
# than inferring it from a download failing, is what keeps "this repo has no
# sums" distinct from "this repo's sums could not be fetched".
release_assets() { # repo version
  gh release view "$2" --repo "$1" --json assets --jq '.assets[].name'
}

# Pull down every asset of a release. The provenance path needs this because
# the attestation is looked up BY ARTIFACT DIGEST — there is nothing to ask
# about until some bytes are on disk — and because the attested subject list
# then vouches for all of them at once.
harvest_release() { # repo version
  local repo="$1" version="$2" dir="downloads/${repo##*/}"
  mkdir -p "$dir"
  gh release download "$version" --repo "$repo" -p '*' -D "$dir"
}

# Turn the attestation's in-toto subject list into the SHA256SUMS.txt the rest
# of this script already knows how to check assets against.
#
# This is the substitution that makes provenance a first-class proof rather
# than a bolt-on: `gh attestation verify` accepts ONE artifact, but the
# statement it verifies names the digest of EVERY asset in the release, so a
# single verified attestation vouches for the whole release exactly as one
# signed sums file does. Each asset is still checked against its own recorded
# digest at fetch time, by the same `sha256sum -c` as before.
sums_from_attestation() { # attestation-json out-file
  python3 - "$1" "$2" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
subjects = doc[0]["verificationResult"]["statement"]["subject"]
with open(sys.argv[2], "w") as out:
    for s in subjects:
        out.write(f"{s['digest']['sha256']}  {s['name']}\n")
if not subjects:
    sys.exit("attestation names no subjects — it vouches for nothing")
PY
}

# Hash what actually arrived. ONLY for the recorded-opt-in path: this is
# trust-on-first-use and proves nothing about origin, which is exactly why
# reaching it requires an operator to state a reason that is then signed into
# the layer.
sums_from_local_bytes() { # dir
  local dir="$1" f base
  : > "$dir/SHA256SUMS.txt"
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    base="${f##*/}"
    case "$base" in SHA256SUMS.txt|SHA256SUMS.txt.cosign.bundle) continue ;; esac
    printf '%s  %s\n' "$(sha256_of "$f")" "$base" >> "$dir/SHA256SUMS.txt"
  done
}

sha256_of() { # file -> bare hex
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

verify_release() { # repo version
  local repo="$1" version="$2"
  local dir="downloads/${repo##*/}"
  local proof signer asserts assets attested optin reason
  mkdir -p "$dir"
  # A repo can appear in BOTH lists — rivet and spar ship tools AND VS Code
  # extensions — and its sums are fetched once. `gh release download` refuses
  # to overwrite, so a second call used to abort the whole deposit under
  # `set -e`.
  if [ -f "$dir/.verified-$version" ]; then
    return 0
  fi
  # Two lists naming the SAME repo at DIFFERENT versions would leave one
  # release's assets checked against the other's sums. Refuse, rather than
  # verify the wrong thing convincingly.
  if [ -f "$dir/SHA256SUMS.txt" ]; then
    echo "::error::$repo is requested at more than one version in this layer \
($(ls "$dir"/.verified-* 2>/dev/null | sed 's#.*/.verified-##' | tr '\n' ' ')and $version) \
— one release per repo per layer, or its sums cannot be trusted"
    exit 1
  fi

  assets="$(release_assets "$repo" "$version")"

  # ── 1. a cosign-signed SHA256SUMS.txt ──────────────────────────────────────
  if printf '%s\n' "$assets" | grep -qx 'SHA256SUMS.txt' \
     && printf '%s\n' "$assets" | grep -qx 'SHA256SUMS.txt.cosign.bundle'; then
    gh release download "$version" --repo "$repo" \
      -p 'SHA256SUMS.txt' -p 'SHA256SUMS.txt.cosign.bundle' -D "$dir"
    # NOT guarded by `if`: a sums file that fails to verify aborts the run. The
    # ladder must never read a rejected signature as an absent one.
    cosign verify-blob \
      --bundle "$dir/SHA256SUMS.txt.cosign.bundle" \
      --certificate-identity-regexp "https://github.com/$repo/" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$dir/SHA256SUMS.txt"
    proof="cosign-sums"
    signer="https://github.com/$repo/"
    asserts="SHA256SUMS.txt signed by an identity under https://github.com/$repo/ via \
token.actions.githubusercontent.com; this payload's recorded asset digest is transcribed from it"
  else
    # ── 2. GitHub build provenance ───────────────────────────────────────────
    harvest_release "$repo" "$version"
    attested=""
    for f in "$dir"/*; do
      [ -f "$f" ] || continue
      case "${f##*/}" in SHA256SUMS.txt*) continue ;; esac
      if gh attestation verify "$f" --repo "$repo" --format json > "$dir/.attestation.json" 2>/dev/null; then
        attested="$f"
        break
      fi
    done
    if [ -n "$attested" ]; then
      sums_from_attestation "$dir/.attestation.json" "$dir/SHA256SUMS.txt"
      signer="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["verificationResult"]["signature"]["certificate"]["buildSignerURI"])' "$dir/.attestation.json")"
      local commit
      commit="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["verificationResult"]["signature"]["certificate"].get("sourceRepositoryDigest",""))' "$dir/.attestation.json")"
      proof="build-provenance"
      asserts="built by $signer from source commit $commit; this payload's recorded asset digest \
is a subject of that attestation"
      echo "::notice::$repo $version has no signed sums but IS attested — ingesting on build \
provenance from $signer"
    else
      # REQ-INGEST-001 clause 3: no mechanism, no ingestion.
      optin=""
      if [ -n "${UNVERIFIED_INGEST:-}" ]; then
        local saved_ifs="$IFS" entry
        IFS='
'
        for entry in $UNVERIFIED_INGEST; do
          case "$entry" in
            "$repo="*) optin="yes"; reason="${entry#*=}" ;;
          esac
        done
        IFS="$saved_ifs"
      fi
      if [ -n "$optin" ] && [ -n "${reason// /}" ]; then
        sums_from_local_bytes "$dir"
        proof="unverified"
        signer=""
        asserts="NOTHING vouched for these bytes — ingested on an explicit operator opt-in. \
Recorded reason: $reason"
        echo "::warning::$repo $version was ingested with NO proof of origin. The layer records \
proof = \"unverified\" and your reason: $reason"
      elif [ -n "$optin" ]; then
        echo "::error::UNVERIFIED_INGEST names $repo but records no reason. \"We could not \
verify this\" must never be the silent path — the reason is what travels with the bytes into the \
signed layer, so it is not optional. Write UNVERIFIED_INGEST=\"$repo=<why>\"."
        exit 1
      else
        # REQ-INGEST-001 clauses 3 and 4 — THE REFUSAL. The system gate deletes
        # everything from this line to the `exit 1` below and requires the
        # unproven tool to sail through, which is what proves the refusal is
        # what stops it rather than some accident of the fixture.
        echo "::error::$repo $version offers no ingestion proof this assembler accepts:
  - no cosign-signed SHA256SUMS.txt (the release publishes neither SHA256SUMS.txt nor
    SHA256SUMS.txt.cosign.bundle)
  - no GitHub build provenance (\`gh attestation verify\` found no attestation for any of its
    assets)
varve will not sign bytes that nothing vouched for into a layer other people install.
The alternative that exists, and the one to reach for first: fork $repo into this organisation and
cut its release through the PulseEngine signed pipeline, whose release.yml publishes a
cosign-signed SHA256SUMS.txt — then name the fork here instead of upstream. That is not a
theoretical suggestion: it is what this organisation already does for every tool in the layer, and
for bytecodealliance/wit-bindgen it is the whole answer, because upstream publishes tarballs and
nothing else.
To ingest it anyway you must say why, and the reason is signed into the layer:
  UNVERIFIED_INGEST=\"$repo=<why this is acceptable, and what removes the need>\"
which stamps proof = \"unverified\" and your words onto every payload from this release, where
\`varve inspect\` and every consumer will read them."
        exit 1
      fi
    fi
  fi

  # Recorded only AFTER a mechanism has accepted, so a failed verification is
  # never cached as success — and the mechanism is written down per repo, since
  # it has to reach every payload's [tool.source] block.
  printf '%s' "$proof"   > "$dir/.proof"
  printf '%s' "$signer"  > "$dir/.proof-signer"
  printf '%s' "$asserts" > "$dir/.proof-asserts"
  touch "$dir/.verified-$version"
}

# The three ingestion-proof lines of a [tool.source] block, for the repo whose
# release this payload came from.
emit_proof() { # repo
  local dir="downloads/${1##*/}" signer
  [ -f "$dir/.proof" ] || return 0
  printf 'proof = "%s"\n' "$(cat "$dir/.proof")"
  signer="$(cat "$dir/.proof-signer")"
  # Absent, never empty: `proof-signer = ""` would be a signed claim that
  # somebody vouched and declined to say who. `varve deposit` refuses a signer
  # on an `unverified` payload for the same reason.
  if [ -n "$signer" ]; then
    printf 'proof-signer = "%s"\n' "$(toml_str "$signer")"
  fi
  printf 'proof-asserts = "%s"\n' "$(toml_str "$(cat "$dir/.proof-asserts")")"
}

asset_sha() { # repo asset -> hash from the VERIFIED sums (empty if absent)
  local dir="downloads/${1##*/}"
  # pipefail-safe: a missing asset is an EXPECTED empty answer, not an error —
  # the caller skips it with a notice.
  { grep -E "[ /]$2\$" "$dir/SHA256SUMS.txt" || true; } | awk '{print $1}' | head -1
}

fetch_asset() { # repo version asset
  local repo="$1" version="$2" asset="$3"
  local dir="downloads/${repo##*/}"
  # Idempotent for the same reason verify_release is; the checksum below is
  # what actually decides the bytes are right.
  [ -f "$dir/$asset" ] || gh release download "$version" --repo "$repo" -p "$asset" -D "$dir"
  (cd "$dir" && grep -E "[ /]$asset\$" SHA256SUMS.txt | sed 's# \./# #' | sha256sum_c)
}

SPEC="$WORK/deposit-spec.toml"
printf 'layer = "%s"\nchannel = "rolling"\ncounter = %s\n' "$LAYER" "$COUNTER" > "$SPEC"

add_tool() { # name version platform path repo release asset sha
  cat >> "$SPEC" <<TOMLEOF

[[tool]]
name = "$1"
version = "$2"
platform = "$3"
path = "$4"

[tool.source]
repo = "$5"
release = "$6"
asset = "$7"
sha256 = "$8"
TOMLEOF
  emit_proof "$5" >> "$SPEC"
}

# The short platform tags used outside this organisation. bytecodealliance
# names its assets `<tool>-<version>-aarch64-macos.tar.gz`, not by Rust target
# triple, so ingesting a second realm needs the mapping written down rather
# than assumed. Recorded from the live v1.257.1 asset list, 2026-08-21.
upstream_platform_tag() {
  case "$1" in
    aarch64-apple-darwin)      echo "aarch64-macos";;
    x86_64-apple-darwin)       echo "x86_64-macos";;
    aarch64-unknown-linux-gnu) echo "aarch64-linux";;
    x86_64-unknown-linux-gnu)  echo "x86_64-linux";;
  esac
}

# Standard tarball tools — include every platform the release ships.
for entry in $TARBALL_TOOLS; do
  # [owner/]tool : version [: binary [: asset-template]]
  # Every optional field keeps its old default, so the entries this workflow
  # already ships (`rivet:v0.33.1`, `kiln:v0.4.4:kilnd`) parse to exactly what
  # they parsed to before.
  IFS=':' read -r f_tool f_version f_binary f_template <<ENTRYEOF
$entry
ENTRYEOF
  case "$f_tool" in
    */*) repo="$f_tool"; tool="${f_tool##*/}" ;;
    *)   repo="pulseengine/$f_tool"; tool="$f_tool" ;;
  esac
  version="$f_version"
  binname="${f_binary:-$tool}"
  bare="${version#v}"
  template="${f_template:-$tool-$version-%T.tar.gz}"
  verify_release "$repo" "$version"
  for platform in $PLATFORMS; do
    asset="${template//%V/$bare}"
    asset="${asset//%T/$platform}"
    asset="${asset//%U/$(upstream_platform_tag "$platform")}"
    sha="$(asset_sha "$repo" "$asset")"
    if [ -z "$sha" ]; then
      echo "::notice::$tool has no asset for $platform — layer omits it there"
      continue
    fi
    fetch_asset "$repo" "$version" "$asset"
    mkdir -p "extract/$tool-$platform"
    tar xzf "downloads/$tool/$asset" -C "extract/$tool-$platform"
    # Layouts differ per repo (flat vs versioned subdir): locate the binary by
    # name anywhere in the extraction.
    bin="$(find "extract/$tool-$platform" -type f -name "$binname" | head -1)"
    if [ -z "$bin" ]; then
      echo "::error::$asset contains no '$binname' binary; contents:"; tar tzf "downloads/$tool/$asset" | head -20
      exit 1
    fi
    cp "$bin" "tools/$binname-$platform"
    add_tool "$binname" "$bare" "$platform" "tools/$binname-$platform" "$repo" "$version" "$asset" "$sha"
  done
done

# wsc: raw per-platform binaries with sigil's naming.
verify_release pulseengine/sigil "$WSC_VERSION"
BARE_WSC="${WSC_VERSION#v}"
for platform in $PLATFORMS; do
  case "$platform" in
    aarch64-apple-darwin)      wsc_asset="wsc-macos-aarch64";;
    x86_64-apple-darwin)       wsc_asset="wsc-macos-x86_64";;
    aarch64-unknown-linux-gnu) wsc_asset="wsc-linux-aarch64";;
    x86_64-unknown-linux-gnu)  wsc_asset="wsc-linux-x86_64";;
  esac
  sha="$(asset_sha pulseengine/sigil "$wsc_asset")"
  if [ -z "$sha" ]; then
    echo "::notice::wsc has no asset for $platform — layer omits it there"
    continue
  fi
  fetch_asset pulseengine/sigil "$WSC_VERSION" "$wsc_asset"
  cp "downloads/sigil/$wsc_asset" "tools/wsc-$platform"
  add_tool wsc "$BARE_WSC" "$platform" "tools/wsc-$platform" pulseengine/sigil "$WSC_VERSION" "$wsc_asset" "$sha"
done

# VS Code extensions (REQ-VSIX-001). A vsix is HELD, not dispatched, so the
# entry carries no binary and `varve export-vsix` is what materialises it for
# `code --install-extension`.
add_vsix() { # name version platform path repo release asset sha
  local plat_line=""
  [ -n "$3" ] && plat_line="platform = \"$3\""
  cat >> "$SPEC" <<TOMLEOF

[[tool]]
name = "$1"
version = "$2"
kind = "vsix"
$plat_line
path = "$4"

[tool.source]
repo = "$5"
release = "$6"
asset = "$7"
sha256 = "$8"
TOMLEOF
  emit_proof "$5" >> "$SPEC"
}

# VSIX platform tags are VS Code's, not Rust target triples.
vsix_platform_tag() {
  case "$1" in
    aarch64-apple-darwin)      echo "darwin-arm64";;
    x86_64-apple-darwin)       echo "darwin-x64";;
    aarch64-unknown-linux-gnu) echo "linux-arm64";;
    x86_64-unknown-linux-gnu)  echo "linux-x64";;
  esac
}

for entry in $VSIX_PACKAGES; do
  repo_name="${entry%%:*}"; rest="${entry#*:}"
  version="${rest%%:*}";    rest="${rest#*:}"
  extname="${rest%%:*}";    template="${rest#*:}"
  bare="${version#v}"
  repo="pulseengine/$repo_name"
  verify_release "$repo" "$version"
  if [ "${template#*%P}" = "$template" ]; then
    # Platform-independent: exactly one package, no platform field.
    asset="${template//%V/$bare}"
    sha="$(asset_sha "$repo" "$asset")"
    if [ -z "$sha" ]; then
      echo "::error::$repo $version ships no $asset — declared in VSIX_PACKAGES"
      exit 1
    fi
    fetch_asset "$repo" "$version" "$asset"
    cp "downloads/$repo_name/$asset" "vsix/$extname-$bare.vsix"
    add_vsix "$extname" "$bare" "" "vsix/$extname-$bare.vsix" "$repo" "$version" "$asset" "$sha"
  else
    found=0
    for platform in $PLATFORMS; do
      tag="$(vsix_platform_tag "$platform")"
      asset="${template//%V/$bare}"; asset="${asset//%P/$tag}"
      sha="$(asset_sha "$repo" "$asset")"
      if [ -z "$sha" ]; then
        echo "::notice::$extname has no vsix for $platform — layer omits it there"
        continue
      fi
      fetch_asset "$repo" "$version" "$asset"
      cp "downloads/$repo_name/$asset" "vsix/$extname-$tag-$bare.vsix"
      add_vsix "$extname" "$bare" "$platform" "vsix/$extname-$tag-$bare.vsix" "$repo" "$version" "$asset" "$sha"
      found=$((found+1))
    done
    # A per-platform extension that matched NOTHING means the asset naming
    # changed upstream. Silence would ship a layer missing an extension it
    # claims to carry.
    [ "$found" -gt 0 ] || { echo "::error::$extname matched no vsix asset for any platform (template $template)"; exit 1; }
  fi
done

echo "── deposit spec: $SPEC"
head -40 "$SPEC"
ls -la "$WORK/tools/"
