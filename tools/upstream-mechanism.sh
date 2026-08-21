#!/usr/bin/env bash
# Which mechanism vouches for an upstream release? — the ingestion-mechanism
# table (REQ-ROLLING-001 clauses 4 and 5).
#
# The layer assembler (tools/build-deposit-spec.sh) verifies every artifact it
# ingests before it is deposited. For most PulseEngine repos that verification
# is a cosign-signed SHA256SUMS.txt; it is NOT the only possible one, and
# hard-coding "cosign" anywhere outside the code that actually runs cosign is
# how a second mechanism becomes a rewrite instead of an entry.
#
# So the mechanism is a VALUE, not an assumption. This file is the table:
#
#   UPSTREAM_MECHANISMS   the ids to try, in order. Overridable from the
#                         environment, so adding a mechanism is adding a
#                         function and a name — never editing the scanner.
#
#   upstream_mechanism <repo> <version> <release-json> <workdir>
#                         prints "<id><TAB><detail>" and returns 0 when some
#                         mechanism VOUCHED for the release; returns 1 when
#                         none did. The detail string is what gets shown to a
#                         human in the proposal, so it names what was checked,
#                         not merely what was present.
#
# "Vouched" means checked, not advertised. A release that merely SHIPS a
# signature file has not been verified; every probe below runs the real
# verification and reports only what came back green. That distinction is the
# whole point of clause 5 — a tool whose new release cannot be verified is held
# at its current pin, and a probe that graded on presence would hold nothing.
#
# Sourced by tools/scan-upstream.sh. Standalone use:
#   . tools/upstream-mechanism.sh
#   upstream_mechanism pulseengine/rivet v0.34.0 rel.json /tmp/probe

# The order is the priority: the first mechanism that vouches wins, and its id
# is what the proposal reports.
UPSTREAM_MECHANISMS="${UPSTREAM_MECHANISMS:-cosign-sums gh-provenance}"

# ── cosign-signed SHA256SUMS.txt ─────────────────────────────────────────────
# What every pulseengine/* release carries today, and exactly what
# build-deposit-spec.sh's verify_release() checks: the sums file is signed by a
# workflow identity under the repo's own namespace, attested to the public
# Sigstore log.
_um_cosign_sums() { # repo version release-json workdir
  local repo="$1" version="$2" rel="$3" work="$4"
  jq -e '[.assets[].name] | index("SHA256SUMS.txt") and index("SHA256SUMS.txt.cosign.bundle")' \
     "$rel" >/dev/null 2>&1 || return 1
  # A probe that cannot run the verifier must not report a verified result.
  command -v cosign >/dev/null 2>&1 || {
    _um_note "cosign is not on PATH — cannot check $repo $version"
    return 1
  }
  local dir="$work/cosign/${repo//\//_}-$version"
  rm -rf "$dir"; mkdir -p "$dir"
  gh release download "$version" --repo "$repo" \
     -p 'SHA256SUMS.txt' -p 'SHA256SUMS.txt.cosign.bundle' -D "$dir" >/dev/null 2>&1 || return 1
  # The identity regexp is the assembler's, character for character. If the two
  # ever disagree the scanner would propose a bump the deposit then refuses.
  cosign verify-blob \
    --bundle "$dir/SHA256SUMS.txt.cosign.bundle" \
    --certificate-identity-regexp "https://github.com/$repo/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$dir/SHA256SUMS.txt" >"$dir/cosign.log" 2>&1 || return 1
  printf 'cosign-sums\t%d sums signed by a workflow under https://github.com/%s/ (cosign verify-blob)\n' \
    "$(wc -l < "$dir/SHA256SUMS.txt" | tr -d ' ')" "$repo"
}

# ── GitHub build provenance ──────────────────────────────────────────────────
# For upstreams that publish no cosign sums — bytecodealliance/wasm-tools is
# the case in hand — but do attach SLSA build provenance to their release
# assets via actions/attest-build-provenance. `gh attestation verify` checks
# the bundle against the repo and the public transparency log, so the trust
# story is the same shape: this artifact was built by that repo's workflow.
#
# Provenance is per-ARTIFACT, so unlike a sums file there is nothing small to
# check that covers the release. The probe verifies one real asset — the
# smallest non-source one — which is what makes it evidence rather than a
# guess about the release's configuration.
_um_gh_provenance() { # repo version release-json workdir
  local repo="$1" version="$2" rel="$3" work="$4"
  gh attestation verify --help >/dev/null 2>&1 || {
    _um_note "this gh has no 'attestation verify' — cannot check $repo $version"
    return 1
  }
  local asset
  asset="$(jq -r '[.assets[] | select(.name | test("\\.(tar\\.gz|tgz|zip|vsix|wasm)$"))]
                  | sort_by(.size) | .[0].name // empty' "$rel")"
  [ -n "$asset" ] || return 1
  local dir="$work/provenance/${repo//\//_}-$version"
  rm -rf "$dir"; mkdir -p "$dir"
  gh release download "$version" --repo "$repo" -p "$asset" -D "$dir" >/dev/null 2>&1 || return 1
  gh attestation verify "$dir/$asset" --repo "$repo" >"$dir/verify.log" 2>&1 || return 1
  printf 'gh-provenance\tbuild provenance verified for %s (gh attestation verify --repo %s)\n' \
    "$asset" "$repo"
}

_um_note() { echo "   note: $*" >&2; }

upstream_mechanism() { # repo version release-json workdir
  local repo="$1" version="$2" rel="$3" work="$4" m out
  for m in $UPSTREAM_MECHANISMS; do
    case "$m" in
      cosign-sums)   out="$(_um_cosign_sums   "$repo" "$version" "$rel" "$work")" || continue ;;
      gh-provenance) out="$(_um_gh_provenance "$repo" "$version" "$rel" "$work")" || continue ;;
      *)
        # A typo in an override must not silently downgrade every tool to
        # "unverifiable" — that would read as an upstream problem.
        echo "::error::UPSTREAM_MECHANISMS names an unknown mechanism '$m'" >&2
        return 2 ;;
    esac
    printf '%s\n' "$out"
    return 0
  done
  return 1
}
