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

# A GitHub build attestation over a whole release (REQ-INGEST-001), written
# NEXT TO the release directory rather than inside it: it is not a release
# asset, and a `-p '*'` download must not pick it up.
#
# The shape is the one `gh attestation verify --format json` printed for
# bytecodealliance/wasm-tools v1.257.1 on 2026-08-21, reduced to the fields the
# assembler reads. The in-toto subject list carries EVERY asset in the release
# — which is what makes an attestation a replacement for the sums file and not
# merely an addition to it.
write_attestation() { # release-dir repo version
  local dir="$1" repo="$2" version="$3"
  python3 - "$dir" "$repo" "$version" <<'PY'
import hashlib, json, os, pathlib, sys

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
    # Which ingestion proof this repo publishes: sums | provenance | none.
    if [ "$repo" = '!proof' ]; then
      mkdir -p "$root/$version"
      printf '%s\n' "$asset" > "$root/$version.proof"
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
      *) fail "fixture: unknown shape '$shape' for $repo $version $asset" ;;
    esac
  done < "$FIXTURES/releases.tsv"

  local proof
  for owner in "$root"/*; do
    [ -d "$owner" ] || continue
    for name in "$owner"/*; do
      [ -d "$name" ] || continue
      style="$(cat "$name.sums-style" 2>/dev/null || echo bare)"
      proof="$(cat "$name.proof" 2>/dev/null || echo sums)"
      for ver in "$name"/*; do
        [ -d "$ver" ] || continue
        case "$proof" in
          sums)       write_sums "$ver" "${owner##*/}/${name##*/}" "${ver##*/}" "$style" ;;
          provenance) write_attestation "$ver" "${owner##*/}/${name##*/}" "${ver##*/}" ;;
          none)       : ;;  # tarballs and nothing else — the refusal case
          *) fail "fixture: unknown !proof '$proof' for ${name##*/}" ;;
        esac
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
  # wasm-tools is in the ORDINARY layer, not in a special case of its own:
  # REQ-INGEST-001 clause 1 says build provenance is a FIRST-CLASS ingestion
  # proof, and a mechanism only exercised by its own scenario is not first
  # class. It is also the entry that drives the foreign-owner and
  # asset-template forms of a TARBALL_TOOLS entry.
  export TARBALL_TOOLS="rivet:v0.33.1 spar:v0.36.0 loom:v1.2.0 kiln:v0.4.4:kilnd \
bytecodealliance/wasm-tools:v1.257.1:wasm-tools:wasm-tools-%V-%U.tar.gz"
  export WSC_VERSION=v0.10.0
  export VSIX_PACKAGES="rivet:v0.33.1:rivet-sdlc:rivet-sdlc-%V.vsix spar:v0.36.0:spar-aadl:spar-aadl-%P-%V.vsix"
  unset VARVE_FIXTURE_COSIGN_REJECT || true
  unset UNVERIFIED_INGEST || true
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

# ── 3b. the ingestion proof reaches the SIGNED payload (REQ-INGEST-001) ──────
# Clause 2. The spec saying `proof = "build-provenance"` proves the assembler
# WROTE it; this proves it SURVIVED into the DSSE-signed layer manifest, which
# is the only place a consumer can read it from. The two are different claims
# and the second is the one the requirement makes.
echo "== the mechanism that vouched for each payload is inside the signed layer"
python3 - "$WORK/layer-layout" <<'PY' || fail "the ingestion proof did not reach the signed layer payload"
import json, pathlib, sys

layout = pathlib.Path(sys.argv[1])
# The signed payload, found the way a consumer finds it: the blob whose
# artifactType says it is a varve layer manifest. Reading a copy the test kept
# would prove the test wrote it, not that the deposit signed it.
payload = None
for blob in sorted((layout / "blobs" / "sha256").iterdir()):
    try:
        doc = json.loads(blob.read_text())
    except (ValueError, UnicodeDecodeError):
        continue
    if doc.get("artifactType") == "application/vnd.pulseengine.varve.layer.v1+json":
        payload = doc
        break
if payload is None:
    sys.exit("no varve layer manifest blob in the deposited layout")

PROOF = "eu.pulseengine.source.proof"
SIGNER = "eu.pulseengine.source.proof-signer"
ASSERTS = "eu.pulseengine.source.proof-asserts"

by_name = {}
for e in payload["manifests"]:
    by_name.setdefault(e["annotations"].get("eu.pulseengine.tool"), []).append(e["annotations"])

problems = []
def want(name, mechanism, signer_contains, asserts_contains):
    entries = by_name.get(name) or []
    if not entries:
        problems.append(f"{name}: no entry in the signed payload at all")
        return
    for a in entries:
        got = a.get(PROOF)
        if got != mechanism:
            problems.append(f"{name}: signed proof is {got!r}, expected {mechanism!r}")
        if signer_contains and signer_contains not in (a.get(SIGNER) or ""):
            problems.append(f"{name}: signed proof-signer {a.get(SIGNER)!r} does not name {signer_contains!r}")
        if asserts_contains and asserts_contains not in (a.get(ASSERTS) or ""):
            problems.append(f"{name}: signed proof-asserts {a.get(ASSERTS)!r} does not state {asserts_contains!r}")

# A cosign-signed repo and an attested one must be DISTINGUISHABLE from inside
# the layer — that is the whole clause.
want("rivet", "cosign-sums", "https://github.com/pulseengine/rivet/", "SHA256SUMS.txt")
want("kilnd", "cosign-sums", "https://github.com/pulseengine/kiln/", "SHA256SUMS.txt")
want("wsc", "cosign-sums", "https://github.com/pulseengine/sigil/", "SHA256SUMS.txt")
want("rivet-sdlc", "cosign-sums", "https://github.com/pulseengine/rivet/", "SHA256SUMS.txt")
# The attestation asserts WHERE the bytes came from, so the workflow and the
# source commit are what it records — not merely "a signature existed".
want("wasm-tools", "build-provenance",
     "bytecodealliance/wasm-tools/.github/workflows/publish.yml", "source commit")

mechanisms = {a.get(PROOF) for entries in by_name.values() for a in entries}
if None in mechanisms:
    unproven = sorted(n for n, es in by_name.items() if any(a.get(PROOF) is None for a in es))
    problems.append(f"payloads carry NO proof annotation at all: {unproven}")
if problems:
    print("signed-payload proof assertions FAILED:", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    sys.exit(1)
print(f"   every payload names its mechanism in the signed layer: {sorted(m for m in mechanisms if m)}")
PY

# `varve inspect` is the operator-facing half of clause 5. It is CLI code and
# not this agent's to change, so the gate asserts the DATA it needs is present
# and reachable, and says plainly what is still missing.
if ( cd "$WORK/project" && PATH="$CLEAN_PATH" "$VARVE" inspect --json ) \
     > "$WORK/logs/inspect.json" 2>"$WORK/logs/inspect.err"; then
  # REQ-INGEST-001 clause 5. This was a NOTE while the CLI wiring was owned by
  # someone else; it is an ASSERTION now, because a clause reported as
  # "not satisfied" by a passing gate is a clause nothing enforces.
  grep -q '"ingest_proof"' "$WORK/logs/inspect.json" || {
    echo "FAIL: clause 5 — the mechanism is in the signed payload but \
\`varve inspect --json\` does not surface it (no \"ingest_proof\" key)" >&2
    exit 1
  }
  # …and it must report the REAL mechanisms this layer mixes, not a constant.
  for mech in build-provenance cosign-sums; do
    grep -q "\"$mech\"" "$WORK/logs/inspect.json" || {
      echo "FAIL: clause 5 — inspect does not report '$mech', which this layer carries" >&2
      exit 1
    }
  done
  # The summary counts exist so a CI gate can assert "nothing went unverified"
  # without walking the payload list.
  grep -q '"unrecorded"' "$WORK/logs/inspect.json" || {
    echo "FAIL: clause 5 — inspect --json summary has no 'unrecorded' count" >&2
    exit 1
  }
  echo "   varve inspect --json reports the mechanism per payload, both kinds, \
and the summary counts"
else
  echo "FAIL: varve inspect --json did not run: $(tail -1 "$WORK/logs/inspect.err")" >&2
  exit 1
fi

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

# A repo that publishes a sums file whose signature does not verify must NOT
# fall through to the provenance path. "This repo has no cosign proof" and
# "this repo's cosign proof is bad" are different facts, and treating the
# second as the first is how a fallback ladder turns a detected attack into a
# quiet downgrade. wasm-tools is in this layer and DOES have provenance, so if
# the ladder were wrong for loom the run would still end green.
reset_layer_env
export VARVE_FIXTURE_COSIGN_REJECT=pulseengine/rivet
expect_refusal cosign-reject-no-downgrade \
  "signature verification failed" \
  "a bad cosign signature falling through to another mechanism instead of stopping"
unset VARVE_FIXTURE_COSIGN_REJECT

# ── 4b. NEITHER mechanism: refused, and told what to do instead ──────────────
# REQ-INGEST-001 clauses 3 and 4. wit-bindgen v0.60.0 publishes no sums and no
# attestation (measured; see the scope note in releases.tsv), so there is
# nothing that vouches for its bytes. "We could not verify this" must never be
# the silent path — and the refusal has to name the alternative that EXISTS,
# because for wit-bindgen a fork released through this org's signed pipeline is
# the answer and an operator should not have to infer it.
reset_layer_env
TARBALL_TOOLS="rivet:v0.33.1 \
bytecodealliance/wit-bindgen:v0.60.0:wit-bindgen:wit-bindgen-%V-%U.tar.gz"
expect_refusal no-ingestion-proof \
  "offers no ingestion proof" \
  "a release with neither a cosign-signed sums file nor build provenance"
for phrase in "fork" "signed pipeline" "UNVERIFIED_INGEST"; do
  grep -qF "$phrase" "$WORK/logs/no-ingestion-proof.log" \
    || { cat "$WORK/logs/no-ingestion-proof.log"
         fail "the refusal does not mention '$phrase' — clause 4 requires it to name the \
alternative that exists and the recorded opt-in, not merely to say no"; }
done
grep -qF "bytecodealliance/wit-bindgen" "$WORK/logs/no-ingestion-proof.log" \
  || fail "the refusal does not name the repo it refused"

# An opt-in with no reason is still the silent path, so it is still refused.
reset_layer_env
TARBALL_TOOLS="rivet:v0.33.1 \
bytecodealliance/wit-bindgen:v0.60.0:wit-bindgen:wit-bindgen-%V-%U.tar.gz"
export UNVERIFIED_INGEST="bytecodealliance/wit-bindgen="
expect_refusal unverified-without-reason \
  "records no reason" \
  "an unverified opt-in that states no reason"
unset UNVERIFIED_INGEST

# ── 4c. the opt-in: allowed, and RECORDED where nobody can miss it ───────────
echo "== an explicit, reasoned opt-in ships the tool and stamps 'unverified' into the layer"
reset_layer_env
TARBALL_TOOLS="rivet:v0.33.1 \
bytecodealliance/wit-bindgen:v0.60.0:wit-bindgen:wit-bindgen-%V-%U.tar.gz"
# The reason carries punctuation an operator would actually write. A separator
# that can occur inside prose truncates it at the moment it matters, so the
# reason is a whole LINE — asserted here rather than assumed.
export UNVERIFIED_INGEST="bytecodealliance/wit-bindgen=no upstream proof exists yet; \
tracked in varve#171, fork planned for 2026.09"

if ! run_assembler unverified-optin; then
  cat "$WORK/logs/unverified-optin.log"
  fail "a reasoned opt-in must be a way THROUGH, or the only options are 'lie' and 'give up'"
fi
grep -qF "::warning::" "$WORK/logs/unverified-optin.log" \
  || fail "the opt-in was taken silently — it must be loud in the log as well as in the layer"
"$VARVE" deposit \
  --spec "$WORK/stage-unverified-optin/deposit-spec.toml" \
  --issued-at "$ISSUED_AT" \
  --key "$WORK/root.key" --key-id systest-deposit-1 \
  --out "$WORK/optin-layout" >"$WORK/logs/optin-deposit.log" 2>&1 \
  || { cat "$WORK/logs/optin-deposit.log"
       fail "varve deposit refused a spec carrying a properly reasoned unverified opt-in"; }
python3 - "$WORK/optin-layout" <<'PY' || fail "the opt-in did not reach the signed layer as 'unverified' with its reason"
import json, pathlib, sys

layout = pathlib.Path(sys.argv[1])
payload = None
for blob in sorted((layout / "blobs" / "sha256").iterdir()):
    try:
        doc = json.loads(blob.read_text())
    except (ValueError, UnicodeDecodeError):
        continue
    if doc.get("artifactType") == "application/vnd.pulseengine.varve.layer.v1+json":
        payload = doc
        break
if payload is None:
    sys.exit("no varve layer manifest blob in the opt-in layout")
PROOF, SIGNER, ASSERTS = ("eu.pulseengine.source.proof",
                          "eu.pulseengine.source.proof-signer",
                          "eu.pulseengine.source.proof-asserts")
seen = 0
for e in payload["manifests"]:
    a = e["annotations"]
    if a.get("eu.pulseengine.tool") != "wit-bindgen":
        continue
    seen += 1
    if a.get(PROOF) != "unverified":
        sys.exit(f"wit-bindgen: signed proof is {a.get(PROOF)!r}, expected 'unverified'")
    if SIGNER in a:
        sys.exit(f"wit-bindgen: nothing vouched for it, yet the layer names signer {a[SIGNER]!r}")
    # The WHOLE reason, punctuation and all — a separator that eats the second
    # half of an operator's sentence is a silent failure of the record clause 3
    # exists to create.
    if "no upstream proof exists yet; tracked in varve#171, fork planned for 2026.09" \
            not in (a.get(ASSERTS) or ""):
        sys.exit(f"wit-bindgen: the operator's recorded reason is not in the layer intact: {a.get(ASSERTS)!r}")
if not seen:
    sys.exit("no wit-bindgen payload in the layer the opt-in was supposed to ship")
print(f"   {seen} opted-in payload(s) carry proof='unverified' and the operator's reason, signed in")
PY
unset UNVERIFIED_INGEST

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

# ── 7. negative control for REQ-INGEST-001 ───────────────────────────────────
# Section 4b is green whenever the assembler stops. It would be green just the
# same if the assembler had stopped for some unrelated reason — a fixture with
# no assets, a typo'd template — and a refusal that fires by accident is not a
# refusal. So delete the refusal from a COPY and require the unproven tool to
# sail straight through. Two facts fall out of one mutation:
#
#   1. the refusal IS what produced 4b's red (with it gone, nothing else stops
#      the run), so 4b is not vacuous;
#   2. `varve deposit` still catches the payload at the signing end, because
#      the mutant records `unverified` with no reason. That is defence in
#      depth actually holding, rather than being asserted.
echo "== negative control: with the refusal deleted, an unproven tool must sail through assembly"
MUTANT2="$WORK/build-deposit-spec.no-refusal.sh"
python3 - "$ASSEMBLER" "$MUTANT2" <<'PY'
import sys

MARKER = "        # REQ-INGEST-001 clauses 3 and 4 — THE REFUSAL. The system gate deletes"
END = "        exit 1"
lines = open(sys.argv[1]).read().split('\n')
try:
    i = lines.index(MARKER)
    j = lines.index(END, i)
except ValueError:
    sys.exit("negative control: the REQ-INGEST-001 refusal marker or its `exit 1` has moved or "
             "been reworded. Update this control — it is currently proving nothing.")
# The assets are already on disk (the provenance probe harvested them), so the
# silent path is exactly this: hash what arrived and say nothing about it.
out = lines[:i] + ['        sums_from_local_bytes "$dir"',
                   '        proof=unverified',
                   '        signer=""',
                   '        asserts=""'] + lines[j + 1:]
open(sys.argv[2], 'w').write('\n'.join(out))
PY
chmod +x "$MUTANT2"
reset_layer_env
TARBALL_TOOLS="rivet:v0.33.1 \
bytecodealliance/wit-bindgen:v0.60.0:wit-bindgen:wit-bindgen-%V-%U.tar.gz"
if ! run_assembler no-refusal "$MUTANT2"; then
  cat "$WORK/logs/no-refusal.log"
  fail "with the refusal DELETED the assembler still stopped — so section 4b's red says nothing \
about the refusal, and the clause-3 result above it is vacuous"
fi
grep -qF 'name = "wit-bindgen"' "$WORK/stage-no-refusal/deposit-spec.toml" \
  || fail "the mutant neither refused nor staged the tool — the control is not controlling what \
it claims"
echo "   control: the unproven tool sailed through, so 4b's red is the refusal's doing"
if "$VARVE" deposit \
     --spec "$WORK/stage-no-refusal/deposit-spec.toml" \
     --issued-at "$ISSUED_AT" \
     --key "$WORK/root.key" --key-id systest-deposit-1 \
     --out "$WORK/no-refusal-layout" >"$WORK/logs/no-refusal-deposit.log" 2>&1; then
  cat "$WORK/logs/no-refusal-deposit.log"
  fail "…and then \`varve deposit\` SIGNED it: an unproven payload reached a layer with nothing \
recording that fact. The second guard does not exist."
fi
grep -qF "records no reason" "$WORK/logs/no-refusal-deposit.log" \
  || { cat "$WORK/logs/no-refusal-deposit.log"
       fail "deposit refused the mutant's spec, but not as an unproven payload — the second \
guard is not the one being credited"; }
echo "   …and the signing end caught it anyway: proof = \"unverified\" recording no reason"

echo "== deposit-layer systest: PASS — layer assembled (cosign-signed AND attested upstreams), \
deposited, installed, verified and exported; an unproven upstream is refused with the fork named, \
a reasoned opt-in is recorded in the layer, and the gate goes red when either guard is removed"
