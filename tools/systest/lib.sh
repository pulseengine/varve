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

# Sign a deposit spec into a layer and pin a project on it.
#
# Everything a gate needs after it has WRITTEN a spec, and nothing about where
# the spec came from: keygen, deposit, the baseline line-status, the pinned
# consumer project, the environment. It was extracted from `systest_make_layer`
# when the `export-wit` gate needed the same dance around a different spec — a
# second copy would have been a second thing to keep in step with
# deposit-layer.yml, which is the defect shape this repo keeps finding.
#
# Arguments: work-dir, spec path, layer, and a key-id suffix so two layers
# signed into the same work dir do not overwrite each other's key.
#
# On return:
#   $work/<pfx>layout     the signed oci-layout (baseline line-status attached)
#   $work/<pfx>root.pub   the trust root the layer verifies against
#   $work/<pfx>project    a directory whose varve.toml pins the layer
#   LAYOUT, PROJECT set; VARVE_ROOT, VARVE_TRUST_ROOT exported
systest_sign_spec_and_pin() { # work spec layer [prefix]
  local work="$1" spec="$2" layer="$3" pfx="${4:-}"
  local line="${layer%.*}"
  local issued_at support_until
  issued_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  LAYOUT="$work/${pfx}layout"
  PROJECT="$work/${pfx}project"

  "$VARVE" keygen --out "$work/${pfx}root.key" --pub "$work/${pfx}root.pub"
  "$VARVE" deposit \
    --spec "$spec" \
    --issued-at "$issued_at" \
    --key "$work/${pfx}root.key" --key-id systest-root-1 \
    --out "$LAYOUT"

  # A baseline line-status, exactly as deposit-layer.yml attaches one: the
  # registry push recipe reads it, and `varve status` works after install.
  # REQ-SUPPORTUNTIL-001: derived, exactly as deposit-layer.yml does it.
  # `sign-status` refuses a document with no support window.
  support_until="$("$VARVE" support-horizon --channel rolling --issued-at "$issued_at")"
  printf '{"line":"%s","counter":1,"issued-at":"%s","support-until":"%s"}\n' \
    "$line" "$issued_at" "$support_until" > "$work/${pfx}baseline-status.json"
  "$VARVE" sign-status \
    --file "$work/${pfx}baseline-status.json" \
    --key "$work/${pfx}root.key" --key-id systest-root-1 \
    --out "$work/${pfx}baseline-status.dsse.json"
  "$VARVE" attach-status --layout "$LAYOUT" --status "$work/${pfx}baseline-status.dsse.json"

  mkdir -p "$PROJECT"
  printf 'manifest-version = 1\n[toolchain]\nchannel = "rolling"\nlayer = "%s"\n' \
    "$layer" > "$PROJECT/varve.toml"

  export VARVE_ROOT="$work/${pfx}varve-root"
  export VARVE_TRUST_ROOT="$work/${pfx}root.pub"
}

# Deposit varve's own Cargo.lock as a layer and pin a project on it.
#
# On return: as `systest_sign_spec_and_pin` with no prefix — $work/layout,
# $work/root.pub, $work/project, VARVE_ROOT, VARVE_TRUST_ROOT, and $LAYER.
systest_make_layer() {
  local repo="$1" work="$2"
  LAYER="${VARVE_SYSTEST_LAYER:-2026.08.0}"

  # Populate the real cargo cache with every .crate the lock pins. This is
  # the ONLY network step; everything downstream must hold offline.
  (cd "$repo" && cargo fetch --locked)

  python3 "$repo/tools/systest/gen-crate-deposit-spec.py" \
    --lock "$repo/Cargo.lock" \
    --cache "${CARGO_HOME:-$HOME/.cargo}/registry/cache" \
    --layer "$LAYER" --channel rolling --counter 1 \
    --out "$work/deposit-spec.toml"

  systest_sign_spec_and_pin "$work" "$work/deposit-spec.toml" "$LAYER"
}

# ── a real OCI registry and a standard client ────────────────────────────────
# Extracted from oci-roundtrip.sh when the line-index gate needed the same
# registry: two copies of a pinned-download-and-checksum block is two things to
# keep in step, and the pins are the part that must not drift.
#
# Everything here is sha256-pinned, never a mutable ref. Sets ORAS and
# REGISTRY. Callers need $WORK/bin to exist.
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

# Push a deposited oci-layout into a registry with a STANDARD client, exactly
# as `varve docs deploy` documents it. ONE recipe: the line-index gate pushes
# two layers through it, and a second copy of this jq would be a second thing
# to keep in step with the documented one.
#
#   $1 layout dir   $2 repo ref (host/path)   $3 tag
# Sets SYSTEST_PAYLOAD_DIGEST — what a pin's `digest` names and what a line
# index entry must carry, so a caller need not re-derive it.
systest_push_layout() {
  local LAYOUT="$1" REPO_REF="$2" TAG="$3"
  local SIG_TYPE='application/vnd.pulseengine.varve.signature.v1+json'
  local STATUS_TYPE='application/vnd.pulseengine.varve.line-status.v1+json'
  local PAYLOAD_DIGEST ENVELOPE_DIGEST STATUS_DIGEST COUNT digest scratch
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/varve-push.XXXXXX")"

  PAYLOAD_DIGEST=$(jq -r --arg t "$SIG_TYPE" --arg s "$STATUS_TYPE" \
    '[.manifests[] | select(.artifactType != $t and .artifactType != $s)][0].digest' "$LAYOUT/index.json")
  ENVELOPE_DIGEST=$(jq -r --arg t "$SIG_TYPE" \
    '[.manifests[] | select(.artifactType == $t)][0].digest' "$LAYOUT/index.json")
  STATUS_DIGEST=$(jq -r --arg s "$STATUS_TYPE" \
    '[.manifests[] | select(.artifactType == $s)][0].digest // empty' "$LAYOUT/index.json")
  test -n "$STATUS_DIGEST" || systest_fail "baseline line-status missing from $LAYOUT"
  blob() { echo "$LAYOUT/blobs/sha256/${1#sha256:}"; }

  printf '{}' > "$scratch/empty-config.json"
  "$ORAS" blob push --plain-http "$REPO_REF" "$scratch/empty-config.json" >/dev/null
  "$ORAS" blob push --plain-http "$REPO_REF" "$(blob "$ENVELOPE_DIGEST")" >/dev/null
  "$ORAS" blob push --plain-http "$REPO_REF" "$(blob "$PAYLOAD_DIGEST")" >/dev/null
  COUNT=0
  for digest in $(jq -r '.manifests[].digest' "$(blob "$PAYLOAD_DIGEST")"); do
    "$ORAS" blob push --plain-http "$REPO_REF" "$(blob "$digest")" >/dev/null
    COUNT=$((COUNT + 1))
  done
  echo "   pushed $COUNT payload blob(s) for $TAG"
  "$ORAS" blob push --plain-http "$REPO_REF" "$(blob "$STATUS_DIGEST")" >/dev/null

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
    }' > "$scratch/artifact-manifest.json"
  "$ORAS" manifest push --plain-http "$REPO_REF:$TAG" "$scratch/artifact-manifest.json" >/dev/null
  SYSTEST_PAYLOAD_DIGEST="$PAYLOAD_DIGEST"
  rm -rf "$scratch"
}
