#!/usr/bin/env bash
# One-off measurement for REQ-VERIFYPAR-001 clause 1 (and the clause 4 baseline).
#
# Question: on a COLD page cache, does `varve verify` spend its time reading or
# hashing? REQ-VERIFYSTREAM-001 measured a warm figure (0.89 s for a 2.00 GiB
# payload: hash 0.74 s, read 0.136 s) and could not get a cold one. If reading
# dominates here, REQ-VERIFYPAR-001 is withdrawn rather than implemented.
#
# The instrument is `varve verify --timing`, which prints ONE line per layer on
# stderr:
#   timing <layer>: N payload(s), X MiB - read R s (..), hash H s (..),
#   signature S s, manifest M s; verify does not decompress
# read and hash are reported SEPARATELY by varve itself (a timing Read wrapper
# and a timing hasher around the same io::copy), so this script only parses.
#
# The layer is built with the systest path (tools/systest/lib.sh:
# systest_sign_spec_and_pin -> varve keygen/deposit/sign-status/attach-status,
# then varve install --from), entirely offline, with a throwaway key. Only the
# `varve` binary is needed for that; varve-producer is accepted so the workflow
# can hand over both, and only its version is recorded.
#
# Usage: tools/measure/verify-cold.sh [varve] [varve-producer]
#   or   VARVE_BIN=... VARVE_PRODUCER_BIN=... tools/measure/verify-cold.sh
# Env:   WORK_DIR   scratch dir (default: mktemp under $TMPDIR)
#        RUNS       runs per case (default 5)
#        BIG_MIB    size of the large payload in MiB (default 2048)
#        SUMMARY    file the summary is also written to (default: $WORK/summary.txt)
# Exits non-zero if any verify run fails.

set -euo pipefail

VARVE="${1:-${VARVE_BIN:-}}"
PRODUCER="${2:-${VARVE_PRODUCER_BIN:-}}"
if [ -z "$VARVE" ] || [ ! -x "$VARVE" ]; then
  echo "error: need an executable varve (arg 1 or VARVE_BIN)" >&2
  exit 2
fi
RUNS="${RUNS:-5}"
BIG_MIB="${BIG_MIB:-2048}"

HERE="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${WORK_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/varve-verify-cold.XXXXXX")}"
mkdir -p "$WORK"
SUMMARY="${SUMMARY:-$WORK/summary.txt}"
# The large source file is the only thing worth deleting eagerly.
trap 'rm -f "$WORK/big.bin"' EXIT

# shellcheck source=tools/systest/lib.sh
. "$HERE/tools/systest/lib.sh"
export VARVE

now() { python3 -c 'import time; print(f"{time.time():.6f}")'; }

# ── layers ───────────────────────────────────────────────────────────────────
LAYER=2026.10.0
mkdir -p "$WORK/payloads"
echo "== generating ${BIG_MIB} MiB of incompressible random bytes" >&2
head -c "$((BIG_MIB * 1024 * 1024))" /dev/urandom > "$WORK/big.bin"
for i in 1 2 3 4 5; do head -c 65536 /dev/urandom > "$WORK/payloads/small$i.bin"; done

write_spec() { # spec-file big?(1|0) count-of-small
  local spec="$1" big="$2" nsmall="$3" i
  {
    printf 'layer = "%s"\nchannel = "rolling"\ncounter = 1\n' "$LAYER"
    if [ "$big" = 1 ]; then
      printf '\n[[tool]]\nname = "bigsdk"\nversion = "1.0.0"\npath = "%s"\nkind = "sdk"\nsdk-prefix = "/opt/poky/4.0"\n' "$WORK/big.bin"
    fi
    for i in $(seq 1 "$nsmall"); do
      printf '\n[[tool]]\nname = "small%s"\nversion = "1.0.0"\npath = "%s"\nkind = "crate"\n' \
        "$i" "$WORK/payloads/small$i.bin"
    done
  } > "$spec"
}

make_case() { # prefix big nsmall -> sets CASE_PROJECT, CASE_ROOT, CASE_TRUST
  local pfx="$1" big="$2" nsmall="$3"
  write_spec "$WORK/${pfx}spec.toml" "$big" "$nsmall"
  systest_sign_spec_and_pin "$WORK" "$WORK/${pfx}spec.toml" "$LAYER" "$pfx"
  if ! (cd "$PROJECT" && "$VARVE" install --from "$LAYOUT" >"$WORK/${pfx}install.log" 2>&1); then
    cat "$WORK/${pfx}install.log" >&2
    echo "error: install failed for case $pfx" >&2
    exit 1
  fi
  CASE_PROJECT="$PROJECT"; CASE_ROOT="$VARVE_ROOT"; CASE_TRUST="$VARVE_TRUST_ROOT"
}

echo "== building + installing the large layer (1 x ${BIG_MIB} MiB + 5 x 64 KiB)" >&2
make_case big- 1 5
BIG_PROJECT="$CASE_PROJECT"; BIG_ROOT="$CASE_ROOT"; BIG_TRUST="$CASE_TRUST"
# The layout and the store each hold a copy; the source is no longer needed.
rm -f "$WORK/big.bin"
echo "== building + installing the small layer (5 x 64 KiB)" >&2
make_case small- 0 5
SMALL_PROJECT="$CASE_PROJECT"; SMALL_ROOT="$CASE_ROOT"; SMALL_TRUST="$CASE_TRUST"

# ── one verify run ───────────────────────────────────────────────────────────
# prints: read hash signature manifest wall   (seconds)
one_run() { # project root trust cold?
  local project="$1" root="$2" trust="$3" cold="$4" t0 t1 err line wall
  err="$WORK/verify.err"
  if [ "$cold" = 1 ]; then
    sync
    echo 3 | sudo -n tee /proc/sys/vm/drop_caches >/dev/null
  fi
  t0="$(now)"
  if ! (cd "$project" && VARVE_ROOT="$root" VARVE_TRUST_ROOT="$trust" "$VARVE" verify --timing) \
      >"$WORK/verify.out" 2>"$err"; then
    cat "$WORK/verify.out" "$err" >&2
    echo "error: varve verify failed" >&2
    return 1
  fi
  t1="$(now)"
  line="$(grep '^timing ' "$err" | head -n1 || true)"
  if [ -z "$line" ]; then
    cat "$err" >&2
    echo "error: no 'timing' line in verify --timing output" >&2
    return 1
  fi
  wall="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f", b-a}')"
  printf '%s\n' "$line" | awk -v w="$wall" '{
    for (i = 1; i <= NF; i++) {
      if ($i == "read")      r = $(i+1)
      if ($i == "hash")      h = $(i+1)
      if ($i == "signature") s = $(i+1)
      if ($i == "manifest")  m = $(i+1)
    }
    sub(/[,;]$/, "", m)
    printf "%s %s %s %s %s\n", r, h, s, m, w
  }'
}

median() {
  sort -g | awk '{a[NR]=$1} END{
    if (NR == 0) print "-";
    else if (NR % 2) printf "%.3f\n", a[(NR+1)/2];
    else printf "%.3f\n", (a[NR/2] + a[NR/2+1]) / 2 }'
}

FAILED=0
: > "$SUMMARY"
emit() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }

run_case() { # name project root trust cold prime?
  local name="$1" project="$2" root="$3" trust="$4" cold="$5" prime="$6" i res rows="" r h s m w
  if [ "$prime" = 1 ]; then
    if ! one_run "$project" "$root" "$trust" 0 >/dev/null; then
      FAILED=1; emit "CASE $name: priming run FAILED"; return 0
    fi
  fi
  for i in $(seq 1 "$RUNS"); do
    if ! res="$(one_run "$project" "$root" "$trust" "$cold")"; then
      FAILED=1; emit "CASE $name: run $i FAILED"; return 0
    fi
    rows="$rows$res"$'\n'
  done
  emit "=== CASE $name BEGIN"
  emit "# per run, seconds: read hash signature manifest wall"
  i=0
  while read -r r h s m w; do
    [ -n "$r" ] || continue
    i=$((i + 1))
    emit "run=$i read=$r hash=$h signature=$s manifest=$m wall=$w"
  done <<<"$rows"
  col() { printf '%s' "$rows" | awk -v c="$1" 'NF{print $c}' | median; }
  emit "median read=$(col 1) hash=$(col 2) signature=$(col 3) manifest=$(col 4) wall=$(col 5)"
  emit "=== CASE $name END"
}

# ── environment ──────────────────────────────────────────────────────────────
cpu="$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -n1 || true)"
[ -n "$cpu" ] || cpu="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
sha="$(grep -o -m1 -w sha_ni /proc/cpuinfo 2>/dev/null || true)"
emit "=== ENVIRONMENT BEGIN"
emit "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
emit "uname: $(uname -a)"
emit "nproc: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
emit "cpu-model: $cpu"
emit "sha_ni: ${sha:-not-present-or-no-/proc/cpuinfo}"
emit "store-path: $BIG_ROOT"
if [ "$(uname -s)" = Linux ]; then
  emit "store-fs: $(df -T "$BIG_ROOT" | tail -n1)"
else
  emit "store-fs: $(df -P "$BIG_ROOT" | tail -n1) (df -T is Linux-only)"
fi
emit "memory: $(free -g 2>/dev/null | tr '\n' '|' || true)"
emit "varve-version: $("$VARVE" --version)"
if [ -n "$PRODUCER" ] && [ -x "$PRODUCER" ]; then
  emit "varve-producer-version: $("$PRODUCER" --version 2>&1 | head -n1)"
fi
emit "git-sha: $(git -C "$HERE" rev-parse HEAD 2>/dev/null || echo unknown)"
emit "runs-per-case: $RUNS  big-payload-MiB: $BIG_MIB"
emit "=== ENVIRONMENT END"

# ── cases ────────────────────────────────────────────────────────────────────
run_case large-warm "$BIG_PROJECT" "$BIG_ROOT" "$BIG_TRUST" 0 1

if [ "$(uname -s)" = Linux ] && sudo -n true 2>/dev/null; then
  run_case large-cold "$BIG_PROJECT" "$BIG_ROOT" "$BIG_TRUST" 1 0
else
  emit "=== CASE large-cold SKIPPED: needs Linux and passwordless sudo to write /proc/sys/vm/drop_caches (uname=$(uname -s)); no cold figure was taken and none is implied"
fi

run_case small-warm "$SMALL_PROJECT" "$SMALL_ROOT" "$SMALL_TRUST" 0 1

if [ "$FAILED" != 0 ]; then
  echo "error: at least one verify run failed" >&2
  exit 1
fi
echo "== summary written to $SUMMARY" >&2
