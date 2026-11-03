#!/usr/bin/env bash
# `varve export-zephyr-modules` under test — REQ-ZMODEXPORT-001, REQ-SYSTEST-002
# clause 5.
#
# A project ADDS Zephyr modules to its own build; varve carries those blocks and
# never Zephyr. This runs the whole path for real: two module trees deposited as
# `kind = "zephyr-module"` payloads (one `build: depends` on the other), signed,
# installed, verified, and laid out by `export-zephyr-modules` with the CMake
# script that appends them to ZEPHYR_EXTRA_MODULES.
#
# WHAT ONLY A SYSTEM RUN CAN SHOW. The unit tests open archives built in memory.
# Here the bytes cross deposit, signing, an OCI layout, install and verification
# first, and the gate asserts the exported tree is BYTE-IDENTICAL to the module
# that was deposited, that `verify --export` passes and then FAILS on one flipped
# byte, and — where `cmake` exists — that real CMake reads the script both ways
# Zephyr users reach for it: `-C` (west's `-- -C`) and `include()`.
#
# NO PYTHON: nothing here runs it, and the pip refusal below is checked at
# deposit, before anything is signed.
#
# Three negative controls, all REFUSALS: a tree with no zephyr/module.yml, a
# module declaring pip with no opt-in, and an incomplete `depends` closure. The
# last one must write NOTHING — a half export would pass `verify --export`.
#
# Usage: tools/systest/zephyr-export.sh [workdir]

set -euo pipefail

WORK="${1:-$(mktemp -d "${TMPDIR:-/tmp}/varve-zephyrexport.XXXXXX")}"
mkdir -p "$WORK/logs"

# shellcheck source=tools/systest/lib.sh
. "$(dirname "$0")/lib.sh"
REPO="$(systest_repo_root)"

fail() { systest_fail "$@"; }

echo "== zephyr-export: workdir $WORK"
systest_build_varve "$REPO"

# ── two modules, built from plain files ─────────────────────────────────────
SRC="$WORK/src"
mkdir -p "$SRC/gale/zephyr" "$SRC/gale/src" "$SRC/hal_x/zephyr" "$SRC/hal_x/src"
cat > "$SRC/gale/zephyr/module.yml" <<'YML'
name: gale
build:
  cmake: .
  depends:
    - hal_x
YML
printf '# gale\n' > "$SRC/gale/CMakeLists.txt"
printf 'int gale(void) { return 1; }\n' > "$SRC/gale/src/gale.c"
cat > "$SRC/hal_x/zephyr/module.yml" <<'YML'
name: hal_x
build:
  cmake: .
YML
printf '# hal_x\n' > "$SRC/hal_x/CMakeLists.txt"
printf 'int hal_x(void) { return 2; }\n' > "$SRC/hal_x/src/hal_x.c"
tar czf "$WORK/gale.tar.gz" -C "$SRC/gale" .
tar czf "$WORK/hal_x.tar.gz" -C "$SRC/hal_x" .

LAYER=2026.11.0
cat > "$WORK/zephyr-spec.toml" <<SPEC
layer = "$LAYER"
channel = "rolling"
counter = 1

[[tool]]
name = "gale"
version = "0.1.0"
path = "$WORK/gale.tar.gz"
kind = "zephyr-module"

[[tool]]
name = "hal_x"
version = "0.1.0"
path = "$WORK/hal_x.tar.gz"
kind = "zephyr-module"
SPEC

systest_sign_spec_and_pin "$WORK" "$WORK/zephyr-spec.toml" "$LAYER"
cd "$PROJECT"
"$VARVE" install --from "$LAYOUT"
"$VARVE" verify

# ── the export ───────────────────────────────────────────────────────────────
OUT="$WORK/zephyr-modules"
"$VARVE" export-zephyr-modules --out "$OUT" \
  >"$WORK/logs/export.log" 2>&1 \
  || { cat "$WORK/logs/export.log"; fail "export-zephyr-modules failed on the installed layer"; }
cat "$WORK/logs/export.log"

# The tree as stored: byte-identical to what was deposited.
for m in gale hal_x; do
  for f in zephyr/module.yml CMakeLists.txt "src/$m.c"; do
    cmp "$OUT/$m/$f" "$SRC/$m/$f" \
      || fail "$m/$f is not byte-identical to the deposited module"
  done
done
echo "   both module trees byte-identical through deposit -> sign -> install -> export"

# The script appends both, by absolute path, and names the layer.
SCRIPT="$OUT/zephyr-extra-modules.cmake"
test -f "$SCRIPT" || fail "no zephyr-extra-modules.cmake was written"
CANON="$(cd "$OUT" && pwd -P)"
for m in gale hal_x; do
  grep -qxF "list(APPEND ZEPHYR_EXTRA_MODULES \"$CANON/$m\")" "$SCRIPT" \
    || { cat "$SCRIPT"; fail "the script does not append $m by absolute path"; }
done
grep -q "$LAYER" "$SCRIPT" || fail "the script does not name the layer"

# The team's west.yml is never made or touched.
test ! -e "$OUT/west.yml" || fail "the export wrote a west.yml"
echo "   the script appends both modules and no west.yml exists"

# ── stamped, and verify --export is not a rubber stamp ──────────────────────
grep -q '"kind": *"zephyr-module"' "$OUT/.varve-export.json" \
  || fail "the export is not stamped kind=zephyr-module"
"$VARVE" verify --export "$OUT" >"$WORK/logs/verify-ok.log" 2>&1 \
  || { cat "$WORK/logs/verify-ok.log"; fail "an untouched zephyr export does not verify"; }
cp "$OUT/hal_x/src/hal_x.c" "$WORK/hal_x.c.orig"
printf 'X' | dd of="$OUT/hal_x/src/hal_x.c" bs=1 count=1 conv=notrunc 2>/dev/null
if "$VARVE" verify --export "$OUT" >"$WORK/logs/verify-bad.log" 2>&1; then
  cat "$WORK/logs/verify-bad.log"
  fail "verify --export passed after one byte of a module was changed"
fi
grep -q 'hal_x/src/hal_x.c' "$WORK/logs/verify-bad.log" \
  || { cat "$WORK/logs/verify-bad.log"; fail "the failure does not name the changed file"; }
cp "$WORK/hal_x.c.orig" "$OUT/hal_x/src/hal_x.c"
"$VARVE" verify --export "$OUT" >/dev/null 2>&1 \
  || fail "the restored export does not verify"
echo "   verify --export passes, FAILS on one changed byte, passes when restored"

# ── real CMake reads the script, both ways ──────────────────────────────────
if command -v cmake >/dev/null 2>&1; then
  mkdir -p "$WORK/cmake-project"
  cat > "$WORK/cmake-project/CMakeLists.txt" <<'CMK'
cmake_minimum_required(VERSION 3.20)
project(probe NONE)
if(PROBE_INCLUDE)
  include("${PROBE_INCLUDE}")
endif()
message(STATUS "ZEM=[${ZEPHYR_EXTRA_MODULES}]")
CMK
  # west's `west build ... -- -C script`
  cmake -S "$WORK/cmake-project" -B "$WORK/cmake-build-c" -C "$SCRIPT" \
    >"$WORK/logs/cmake-c.log" 2>&1 || { cat "$WORK/logs/cmake-c.log"; fail "cmake -C failed"; }
  # a plain CMake build
  cmake -S "$WORK/cmake-project" -B "$WORK/cmake-build-inc" "-DPROBE_INCLUDE=$SCRIPT" \
    >"$WORK/logs/cmake-inc.log" 2>&1 || { cat "$WORK/logs/cmake-inc.log"; fail "cmake include() failed"; }
  for log in cmake-c cmake-inc; do
    for m in gale hal_x; do
      grep 'ZEM=\[' "$WORK/logs/$log.log" | grep -qF "$CANON/$m" \
        || { cat "$WORK/logs/$log.log"; fail "$log: $m is not in ZEPHYR_EXTRA_MODULES"; }
    done
  done
  echo "   real cmake: both modules reach ZEPHYR_EXTRA_MODULES via -C and via include()"
else
  echo "   SKIPPED the real-cmake check: cmake is not installed on this runner"
fi

# ── negative control 1: a tree with no zephyr/module.yml ────────────────────
mkdir -p "$WORK/notmod"
printf 'x\n' > "$WORK/notmod/CMakeLists.txt"
tar czf "$WORK/notmod.tar.gz" -C "$WORK/notmod" .
cat > "$WORK/notmod-spec.toml" <<SPEC
layer = "$LAYER"
channel = "rolling"
counter = 1

[[tool]]
name = "notmod"
version = "0.1.0"
path = "$WORK/notmod.tar.gz"
kind = "zephyr-module"
SPEC
"$VARVE" keygen --out "$WORK/neg.key" --pub "$WORK/neg.pub"
if "$VARVE" deposit --spec "$WORK/notmod-spec.toml" --issued-at 2026-11-03T00:00:00Z \
    --key "$WORK/neg.key" --key-id neg-1 --out "$WORK/notmod-layout" \
    >"$WORK/logs/notmod.log" 2>&1; then
  cat "$WORK/logs/notmod.log"
  fail "the deposit signed a tree with no zephyr/module.yml"
fi
grep -q 'zephyr/module.yml' "$WORK/logs/notmod.log" \
  || { cat "$WORK/logs/notmod.log"; fail "the refusal does not name zephyr/module.yml"; }
test ! -e "$WORK/notmod-layout" || fail "a refused deposit left a layout behind"
echo "   a tree with no zephyr/module.yml is refused at deposit"

# ── negative control 2: pip without an opt-in, and with a wrong one ─────────
mkdir -p "$WORK/pymod/zephyr"
cat > "$WORK/pymod/zephyr/module.yml" <<'YML'
name: pymod
package-managers:
  pip:
    requirement-files:
      - scripts/requirements.txt
YML
tar czf "$WORK/pymod.tar.gz" -C "$WORK/pymod" .
pip_spec() { # allow-pip line (may be empty)
  cat <<SPEC
layer = "$LAYER"
channel = "rolling"
counter = 1

[[tool]]
name = "pymod"
version = "0.1.0"
path = "$WORK/pymod.tar.gz"
kind = "zephyr-module"
$1
SPEC
}
pip_spec "" > "$WORK/pip-none.toml"
pip_spec 'allow-pip = ["other.txt"]' > "$WORK/pip-wrong.toml"
pip_spec 'allow-pip = ["scripts/requirements.txt"]' > "$WORK/pip-ok.toml"
for bad in none wrong; do
  if "$VARVE" deposit --spec "$WORK/pip-$bad.toml" --issued-at 2026-11-03T00:00:00Z \
      --key "$WORK/neg.key" --key-id neg-1 --out "$WORK/pip-$bad-layout" \
      >"$WORK/logs/pip-$bad.log" 2>&1; then
    cat "$WORK/logs/pip-$bad.log"
    fail "the deposit signed a pip module with $bad opt-in"
  fi
  grep -q 'scripts/requirements.txt' "$WORK/logs/pip-$bad.log" \
    || { cat "$WORK/logs/pip-$bad.log"; fail "the pip refusal ($bad) does not name the files"; }
done
"$VARVE" deposit --spec "$WORK/pip-ok.toml" --issued-at 2026-11-03T00:00:00Z \
  --key "$WORK/neg.key" --key-id neg-1 --out "$WORK/pip-ok-layout" >/dev/null 2>&1 \
  || fail "the exact opt-in was refused — the control cannot tell a rule from a wall"
echo "   pip is refused with no opt-in and with a wrong one, accepted with the exact one"

# ── negative control 3: an INCOMPLETE closure writes nothing ────────────────
# A layer carrying gale and NOT hal_x. The export must refuse, name both, and
# leave no stamp and no script behind.
cat > "$WORK/partial-spec.toml" <<SPEC
layer = "$LAYER"
channel = "rolling"
counter = 1

[[tool]]
name = "gale"
version = "0.1.0"
path = "$WORK/gale.tar.gz"
kind = "zephyr-module"
SPEC
systest_sign_spec_and_pin "$WORK" "$WORK/partial-spec.toml" "$LAYER" "partial-"
cd "$PROJECT"
"$VARVE" install --from "$LAYOUT"
"$VARVE" verify
PARTIAL_OUT="$WORK/zephyr-partial"
if "$VARVE" export-zephyr-modules --out "$PARTIAL_OUT" >"$WORK/logs/partial.log" 2>&1; then
  cat "$WORK/logs/partial.log"
  fail "export-zephyr-modules wrote a tree whose build: depends is not carried"
fi
grep -q 'gale' "$WORK/logs/partial.log" && grep -q 'hal_x' "$WORK/logs/partial.log" \
  || { cat "$WORK/logs/partial.log"; fail "the refusal does not name both gale and hal_x"; }
if [ -e "$PARTIAL_OUT/.varve-export.json" ] || [ -e "$PARTIAL_OUT/zephyr-extra-modules.cmake" ] \
    || [ -e "$PARTIAL_OUT/gale" ]; then
  find "$PARTIAL_OUT"
  fail "the refusal left a partial export behind"
fi
echo "   an incomplete depends closure is refused by name, and nothing is written"

echo "== zephyr-export: PASS — two modules verified, laid out, and added to ZEPHYR_EXTRA_MODULES"
