# Shared plumbing for the REQ-SYSTEST-001 system gates. Sourced, not run.
#
# The producing half every systest job shares: build varve, turn varve's OWN
# Cargo.lock into a signed layer (250 crate payloads, several names at more
# than one version), and stand up a pinned consumer project around it. The
# consuming half differs per gate (offline Cargo build, OCI registry round
# trip) and lives in the callers.

set -euo pipefail

systest_repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

systest_fail() { echo "FAIL: $*" >&2; exit 1; }

# ── the recorded release inventory ───────────────────────────────────────────
# Shared by every gate that drives tools/build-deposit-spec.sh. It lived inside
# deposit-layer.sh until REQ-REALM2-001 needed a SECOND gate to assemble two
# realms from the same recorded inventory; a copy of it there would have been a
# second thing to keep in step with the fixture data.
#
# Small stand-in bytes, real asset NAMES, real SHA256SUMS shapes, real cosign
# bundle bindings. Nothing here touches the network, and nothing here depends
# on somebody's release still existing at the version the fixture names.

systest_sha256_of() { # file -> bare hex
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

systest_write_sums() { # release-dir repo version sums-style
  local dir="$1" repo="$2" version="$3" style="$4" f base sums
  sums="$dir/SHA256SUMS.txt"
  : > "$sums"
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    base="${f##*/}"
    case "$base" in SHA256SUMS.txt|SHA256SUMS.txt.cosign.bundle) continue ;; esac
    if [ "$style" = "dotslash" ]; then
      printf '%s  ./%s\n' "$(systest_sha256_of "$f")" "$base" >> "$sums"
    else
      printf '%s  %s\n' "$(systest_sha256_of "$f")" "$base" >> "$sums"
    fi
  done
  # What a real sigstore bundle binds together: the signer identity, the
  # issuer, and the digest of the blob it covers.
  cat > "$dir/SHA256SUMS.txt.cosign.bundle" <<BUNDLE
repo=$repo
identity=https://github.com/$repo/.github/workflows/release.yml@refs/tags/$version
issuer=https://token.actions.githubusercontent.com
sha256=$(systest_sha256_of "$sums")
BUNDLE
}

# A GitHub build attestation over a whole release (REQ-INGEST-001), written
# NEXT TO the release directory rather than inside it: it is not a release
# asset, and a `-p '*'` download must not pick it up.
#
# The shape is the one `gh attestation verify --format json` printed for
# bytecodealliance/wasm-tools v1.257.1 on 2026-08-21, reduced to the fields the
# assembler reads. The in-toto subject list carries EVERY asset in the release
# — which is what makes an attestation a replacement for the sums file and not
# merely an addition to it.
systest_write_attestation() { # release-dir repo version
  python3 - "$1" "$2" "$3" <<'PY'
import hashlib, json, pathlib, sys

d, repo, version = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
# A stand-in commit that is stable per release, so the assertion recorded in
# the layer is reproducible across runs (the payload digest depends on it).
commit = hashlib.sha256(f"{repo}@{version}".encode()).hexdigest()[:40]
signer = f"https://github.com/{repo}/.github/workflows/publish.yml@refs/heads/main"
subjects = [
    {"name": f.name, "digest": {"sha256": hashlib.sha256(f.read_bytes()).hexdigest()}}
    for f in sorted(d.iterdir()) if f.is_file()
]
doc = [{"verificationResult": {
    "signature": {"certificate": {
        "subjectAlternativeName": signer,
        "issuer": "https://token.actions.githubusercontent.com",
        "buildSignerURI": signer,
        "sourceRepositoryURI": f"https://github.com/{repo}",
        "sourceRepositoryDigest": commit,
        "sourceRepositoryRef": "refs/heads/main",
        "runnerEnvironment": "github-hosted",
    }},
    "statement": {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": subjects,
    },
}}]
(d.parent / f"{version}.attestation.json").write_text(json.dumps(doc, indent=1))
PY
}

# Materialise every row of a releases.tsv into a release tree.
#   $1 releases.tsv    $2 output root    $3 scratch dir for tar staging
#
# The asset BYTES are a runnable `/bin/sh` script that prints where it came
# from. They were opaque text until REQ-REALM2-001 needed to prove WHICH of two
# same-named binaries a bare name dispatches to — an answer no amount of
# reading paths can give, because the question is which file gets exec'd.
systest_materialise_releases() { # releases.tsv out-root stage-dir
  local tsv="$1" root="$2" stage_root="$3"
  local repo version asset shape dir body binname layout stagedir
  local owner name ver style proof tab
  tab="$(printf '\t')"
  rm -rf "$root" "$stage_root"
  while IFS="$tab" read -r repo version asset shape; do
    case "$repo" in ''|'#'*) continue ;; esac
    if [ "$repo" = '!sums-style' ]; then
      mkdir -p "$root/$version"
      printf '%s\n' "$asset" > "$root/$version.sums-style"
      continue
    fi
    # Which ingestion proof this repo publishes: sums | provenance | none.
    if [ "$repo" = '!proof' ]; then
      mkdir -p "$root/$version"
      printf '%s\n' "$asset" > "$root/$version.proof"
      continue
    fi
    dir="$root/$repo/$version"
    mkdir -p "$dir"
    # Distinct bytes per asset: two payloads that hashed alike would let a
    # per-platform mix-up pass unnoticed. Runnable, so a gate can ask the
    # binary itself which release it came from.
    body="#!/bin/sh
# varve systest fixture payload
echo \"varve-systest-fixture repo=$repo release=$version asset=$asset\"
"
    case "$shape" in
      raw|blob)
        printf '%s' "$body" > "$dir/$asset"
        ;;
      tar:*)
        binname="$(printf '%s' "$shape" | cut -d: -f2)"
        layout="$(printf '%s' "$shape" | cut -d: -f3)"
        stagedir="$stage_root/$repo/$version/${asset%.tar.gz}"
        rm -rf "$stagedir"; mkdir -p "$stagedir"
        if [ "$binname" = "none" ]; then
          # An upstream layout change: an archive with no binary of the
          # declared name anywhere in it.
          printf 'this release ships documentation and nothing executable\n' > "$stagedir/README.md"
        elif [ "$layout" = "nested" ]; then
          mkdir -p "$stagedir/${repo##*/}-$version/bin"
          printf '%s' "$body" > "$stagedir/${repo##*/}-$version/bin/$binname"
          chmod +x "$stagedir/${repo##*/}-$version/bin/$binname"
        elif [ "$layout" = "upstream" ]; then
          # bytecodealliance's shape: one top directory named for the asset,
          # binary at its root beside the licences.
          mkdir -p "$stagedir/${asset%.tar.gz}"
          printf '%s' "$body" > "$stagedir/${asset%.tar.gz}/$binname"
          chmod +x "$stagedir/${asset%.tar.gz}/$binname"
          printf 'Apache-2.0 WITH LLVM-exception\n' > "$stagedir/${asset%.tar.gz}/LICENSE-APACHE"
        else
          printf '%s' "$body" > "$stagedir/$binname"
          chmod +x "$stagedir/$binname"
        fi
        tar czf "$dir/$asset" -C "$stagedir" .
        ;;
      *) systest_fail "fixture: unknown shape '$shape' for $repo $version $asset" ;;
    esac
  done < "$tsv"

  for owner in "$root"/*; do
    [ -d "$owner" ] || continue
    for name in "$owner"/*; do
      [ -d "$name" ] || continue
      style="$(cat "$name.sums-style" 2>/dev/null || echo bare)"
      proof="$(cat "$name.proof" 2>/dev/null || echo sums)"
      for ver in "$name"/*; do
        [ -d "$ver" ] || continue
        case "$proof" in
          sums)       systest_write_sums "$ver" "${owner##*/}/${name##*/}" "${ver##*/}" "$style" ;;
          provenance) systest_write_attestation "$ver" "${owner##*/}/${name##*/}" "${ver##*/}" ;;
          none)       : ;;  # tarballs and nothing else — the refusal case
          *) systest_fail "fixture: unknown !proof '$proof' for ${name##*/}" ;;
        esac
      done
    done
  done
}

# Build (or accept) the varve under test. Sets VARVE.
systest_build_varve() {
  local repo="$1"
  if [ -n "${VARVE_BIN:-}" ]; then
    VARVE="$VARVE_BIN"
  else
    (cd "$repo" && cargo build --release -p varve)
    VARVE="$repo/target/release/varve"
  fi
  "$VARVE" --version
}

# Deposit varve's own Cargo.lock as a layer and pin a project on it.
#
# On return:
#   $WORK/layout          the signed oci-layout (baseline line-status attached)
#   $WORK/root.pub        the trust root the layer verifies against
#   $WORK/project         a directory whose varve.toml pins $LAYER
#   VARVE_ROOT, VARVE_TRUST_ROOT exported for the varve invocations that follow
systest_make_layer() {
  local repo="$1" work="$2"
  LAYER="${VARVE_SYSTEST_LAYER:-2026.08.0}"
  local line="${LAYER%.*}"
  local issued_at
  issued_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Populate the real cargo cache with every .crate the lock pins. This is
  # the ONLY network step; everything downstream must hold offline.
  (cd "$repo" && cargo fetch --locked)

  python3 "$repo/tools/systest/gen-crate-deposit-spec.py" \
    --lock "$repo/Cargo.lock" \
    --cache "${CARGO_HOME:-$HOME/.cargo}/registry/cache" \
    --layer "$LAYER" --channel rolling --counter 1 \
    --out "$work/deposit-spec.toml"

  "$VARVE" keygen --out "$work/root.key" --pub "$work/root.pub"
  "$VARVE" deposit \
    --spec "$work/deposit-spec.toml" \
    --issued-at "$issued_at" \
    --key "$work/root.key" --key-id systest-root-1 \
    --out "$work/layout"

  # A baseline line-status, exactly as deposit-layer.yml attaches one: the
  # registry push recipe reads it, and `varve status` works after install.
  # REQ-SUPPORTUNTIL-001: derived, exactly as deposit-layer.yml does it.
  # `sign-status` refuses a document with no support window.
  local support_until
  support_until="$("$VARVE" support-horizon --channel rolling --issued-at "$issued_at")"
  printf '{"line":"%s","counter":1,"issued-at":"%s","support-until":"%s"}\n' \
    "$line" "$issued_at" "$support_until" > "$work/baseline-status.json"
  "$VARVE" sign-status \
    --file "$work/baseline-status.json" \
    --key "$work/root.key" --key-id systest-root-1 \
    --out "$work/baseline-status.dsse.json"
  "$VARVE" attach-status --layout "$work/layout" --status "$work/baseline-status.dsse.json"

  mkdir -p "$work/project"
  printf 'manifest-version = 1\n[toolchain]\nchannel = "rolling"\nlayer = "%s"\n' \
    "$LAYER" > "$work/project/varve.toml"

  export VARVE_ROOT="$work/varve-root"
  export VARVE_TRUST_ROOT="$work/root.pub"
}
