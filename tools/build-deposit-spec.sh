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
# What it does: download the pinned per-tool releases, VERIFY each one against
# its own repo's cosign identity, and emit a `varve deposit` spec naming every
# payload it staged. It does NOT deposit, sign or publish — the workflow's
# later steps do that, and the system gate deliberately stops before the push.
#
# Usage:  tools/build-deposit-spec.sh <workdir>
#
# Inputs (environment — the workflow's `env:` block is where the layer's
# CONTENTS are bumped in a reviewed diff, so they are not defaulted here):
#   LAYER          layer identifier, e.g. 2026.08.4
#   COUNTER        monotonic per-line release counter
#   TARBALL_TOOLS  "tool:version[:binary] ..."   (binary defaults to the tool name)
#   WSC_VERSION    sigil release carrying the raw per-platform wsc binaries
#   VSIX_PACKAGES  "repo:version:extension:asset-template ..."  (%V bare version,
#                  %P VS Code platform tag; no %P = one portable package)
#   PLATFORMS      optional override of the target triples to include
#
# Outputs, all under <workdir> so the whole staging area is one removable tree:
#   deposit-spec.toml   the spec; payload `path`s are RELATIVE to it, which is
#                       how varve resolves them (deposit.rs: SpecTool::path)
#   tools/  vsix/       the staged payload bytes the spec points at
#   downloads/ extract/ what was fetched and unpacked to produce them
#
# External programs: `gh` (release downloads) and `cosign` (signature
# verification) are taken from PATH, deliberately — that is the seam the system
# test replaces with fixture-backed doubles to stay hermetic. Everything else
# here is the real code path.

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

verify_release() { # repo version
  local repo="$1" version="$2"
  local dir="downloads/${repo##*/}"
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
  gh release download "$version" --repo "$repo" \
    -p 'SHA256SUMS.txt' -p 'SHA256SUMS.txt.cosign.bundle' -D "$dir"
  cosign verify-blob \
    --bundle "$dir/SHA256SUMS.txt.cosign.bundle" \
    --certificate-identity-regexp "https://github.com/$repo/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$dir/SHA256SUMS.txt"
  # Marked only AFTER cosign accepts, so a failed verification is never cached
  # as success.
  touch "$dir/.verified-$version"
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
}

# Standard tarball tools — include every platform the release ships.
for entry in $TARBALL_TOOLS; do
  tool="${entry%%:*}"
  rest="${entry#*:}"
  version="${rest%%:*}"
  binname="${rest#*:}"; [ "$binname" = "$version" ] && binname="$tool"
  bare="${version#v}"
  repo="pulseengine/$tool"
  verify_release "$repo" "$version"
  for platform in $PLATFORMS; do
    asset="$tool-$version-$platform.tar.gz"
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
