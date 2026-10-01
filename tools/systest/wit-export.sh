#!/usr/bin/env bash
# `varve export-wit` under test — REQ-WIT-001 clause 3, REQ-SYSTEST-002 clause 5.
#
# A layer carries WIT packages FLAT, one payload per `namespace:name@version`.
# A consumer wants one package treated as top level with everything it needs
# beside it. This runs that whole path for real: two separately-encoded binary
# packages deposited as `kind = "wit"` payloads, signed, installed, verified,
# and composed by `export-wit` into the layout `wkg`'s local backend reads.
#
# WHAT ONLY A SYSTEM RUN CAN SHOW. The unit tests index packages from bytes
# handed to them directly; here the bytes travel through deposit, signing, an
# OCI layout, install and verification before anything decodes them. The gate
# asserts they come out BYTE-IDENTICAL — the "copy, not a conversion" claim
# that makes the digest in the layer and the digest on disk the same number.
#
# And the closure is not told to the command: `export-wit` is asked for
# `acme:app@0.3.0` alone, and `acme:base@2.0.0` must appear beside it because
# the app's own signed bytes say it imports it.
#
# Two negative controls at the end, both REFUSALS, because the failure that
# matters here is a tree that is quietly too small: a half-written WIT tree
# parses far enough to fail inside wit-bindgen with a message about an
# interface, and the operator then debugs their WIT instead of their layer.
#
# Usage: tools/systest/wit-export.sh [workdir]

set -euo pipefail

WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/varve-witexport.XXXXXX")}"
mkdir -p "$WORK/logs"

# shellcheck source=tools/systest/lib.sh
. "$(dirname "$0")/lib.sh"
REPO="$(systest_repo_root)"
FIXTURES="$REPO/tools/systest/fixtures/wit"

fail() { systest_fail "$@"; }

echo "== wit-export: workdir $WORK"
systest_build_varve "$REPO"

# ── a layer carrying both packages, flat ────────────────────────────────────
# Written by hand rather than through the assembler: `wit` has no production
# shape yet (the assembler mines releases for binaries), and the deposit spec
# is the same file either way. gen-crate-deposit-spec.py takes the same route.
LAYER=2026.10.0
cat > "$WORK/wit-spec.toml" <<SPEC
layer = "$LAYER"
channel = "rolling"
counter = 1

[[tool]]
name = "acme:base@2.0.0"
version = "2.0.0"
path = "$FIXTURES/acme-base-2.0.0.wasm"
kind = "wit"

[[tool]]
name = "acme:app@0.3.0"
version = "0.3.0"
path = "$FIXTURES/acme-app-0.3.0.wasm"
kind = "wit"
SPEC

systest_sign_spec_and_pin "$WORK" "$WORK/wit-spec.toml" "$LAYER"
cd "$PROJECT"
"$VARVE" install --from "$LAYOUT"
"$VARVE" verify

# ── the export: ask for the app, get the closure ────────────────────────────
OUT="$WORK/wit-export"
"$VARVE" export-wit --package 'acme:app@0.3.0' --out "$OUT" \
  >"$WORK/logs/export-wit.log" 2>&1 \
  || { cat "$WORK/logs/export-wit.log"; fail "export-wit failed on the installed layer"; }
cat "$WORK/logs/export-wit.log"

# The layout is wkg's: <namespace>/<name>/<version>.wasm, and nothing else.
test -f "$OUT/acme/app/0.3.0.wasm" \
  || fail "the package asked for is not at the path wkg reads (<ns>/<name>/<version>.wasm)"
test -f "$OUT/acme/base/2.0.0.wasm" \
  || fail "the dependency was NOT written — the closure came from a list, not from the bytes"

N_WASM="$(find "$OUT" -name '*.wasm' | wc -l | tr -d ' ')"
[ "$N_WASM" = "2" ] || { find "$OUT" -name '*.wasm'; fail "expected 2 packages, wrote $N_WASM"; }

# A copy, not a conversion. The bytes crossed deposit, signing, an OCI layout,
# install and verification; if any of those re-encoded a package, the digest in
# the layer and the digest on disk would be different numbers for one package.
cmp "$OUT/acme/app/0.3.0.wasm" "$FIXTURES/acme-app-0.3.0.wasm" \
  || fail "the exported app package is not byte-identical to what was deposited"
cmp "$OUT/acme/base/2.0.0.wasm" "$FIXTURES/acme-base-2.0.0.wasm" \
  || fail "the exported base package is not byte-identical to what was deposited"
echo "   both packages byte-identical through deposit -> sign -> install -> export"

# The report names the closure, so an operator can see what they got.
grep -q 'acme:base@2.0.0' "$WORK/logs/export-wit.log" \
  || fail "the export wrote the dependency but did not report it"

# ── --registry prints a stanza and edits nothing ────────────────────────────
"$VARVE" export-wit --package 'acme:app@0.3.0' --out "$OUT" --registry acme.example \
  >"$WORK/logs/export-wit-registry.log" 2>&1 \
  || { cat "$WORK/logs/export-wit-registry.log"; fail "export-wit --registry failed"; }
grep -q '\[registry."acme.example".local\]' "$WORK/logs/export-wit-registry.log" \
  || { cat "$WORK/logs/export-wit-registry.log"; fail "--registry printed no wkg stanza"; }
grep -q "root = \"$OUT\"" "$WORK/logs/export-wit-registry.log" \
  || { cat "$WORK/logs/export-wit-registry.log"; fail "the stanza does not point at what was exported"; }
echo "   --registry printed a stanza naming the exported tree"

# ── negative control 1: a package the layer does not carry ──────────────────
# The gate must be able to go red. If this succeeded, every assertion above
# would be reporting on a command that cannot refuse anything.
if "$VARVE" export-wit --package 'acme:absent@9.9.9' --out "$WORK/nope" \
    >"$WORK/logs/absent.log" 2>&1; then
  cat "$WORK/logs/absent.log"
  fail "export-wit composed a package the layer does not carry"
fi
echo "   a package the layer does not carry is refused"

# ── negative control 2: an INCOMPLETE layer writes nothing ──────────────────
# The one that matters. A second layer carrying only the app, with its
# dependency absent: `export-wit` must refuse rather than write a tree that is
# one package short.
cat > "$WORK/wit-spec-incomplete.toml" <<SPEC
layer = "$LAYER"
channel = "rolling"
counter = 1

[[tool]]
name = "acme:app@0.3.0"
version = "0.3.0"
path = "$FIXTURES/acme-app-0.3.0.wasm"
kind = "wit"
SPEC

systest_sign_spec_and_pin "$WORK" "$WORK/wit-spec-incomplete.toml" "$LAYER" "partial-"
cd "$PROJECT"
"$VARVE" install --from "$LAYOUT"
"$VARVE" verify

PARTIAL_OUT="$WORK/wit-export-partial"
if "$VARVE" export-wit --package 'acme:app@0.3.0' --out "$PARTIAL_OUT" \
    >"$WORK/logs/partial.log" 2>&1; then
  cat "$WORK/logs/partial.log"
  find "$PARTIAL_OUT" -name '*.wasm'
  fail "export-wit wrote a tree from a layer missing acme:base@2.0.0 — a short tree \
fails later inside wit-bindgen with a message about an interface"
fi
grep -q 'acme:base@2.0.0' "$WORK/logs/partial.log" \
  || { cat "$WORK/logs/partial.log"; fail "the refusal does not name the missing package"; }
# Nothing, not even the package it could have resolved.
if [ -d "$PARTIAL_OUT" ] && find "$PARTIAL_OUT" -name '*.wasm' | grep -q .; then
  find "$PARTIAL_OUT" -name '*.wasm'
  fail "the refusal left a partial tree behind"
fi
echo "   an incomplete layer is refused by name, and nothing is written"

echo "== wit-export: PASS — a flat layer composed into the layout wkg reads, bytes untouched"
