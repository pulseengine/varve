#!/usr/bin/env bash
# REQ-INSTALLSHADOW-001: the installer must say which varve will actually run.
#
# A maintainer followed the documented install and ended up running a different
# binary than the one it installed: ~/.varve/bin/varve at 0.25.0 from the
# installer, ~/.cargo/bin/varve at 0.29.0 from cargo, and plain `varve`
# resolving to the cargo one. The installer said "Installed …" and even
# "$INSTALL_DIR is already on PATH" -- true, and useless, because being on PATH
# is not being FIRST on it.
#
# varve refuses to claim success when PATH shadows a pinned tool
# (REQ-SHADOW-001). This gate holds varve's own installer to that standard.
#
# It runs install.sh's OWN check_shadow (via VARVE_INSTALL_SHADOW_CHECK_ONLY=1)
# against a fabricated PATH; no copy of the logic lives here, so changing the
# real condition changes this gate's verdict.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/installed/bin" "$WORK/other/bin"
printf '#!/bin/sh\necho "varve 9.9.9"\n' > "$WORK/installed/bin/varve"
printf '#!/bin/sh\necho "varve 0.25.0"\n' > "$WORK/other/bin/varve"
chmod +x "$WORK/installed/bin/varve" "$WORK/other/bin/varve"

# Run install.sh's real check with PATH set to $1; prints its output.
run_check() {
  VARVE_INSTALL_SHADOW_CHECK_ONLY=1 VARVE_INSTALL_DIR="$WORK/installed/bin" \
    PATH="$1" sh "$HERE/install.sh" 2>&1
}

# rivet: verifies REQ-INSTALLSHADOW-001
echo "== the warning must FIRE, and name the winner, when another varve wins PATH"
out="$(run_check "$WORK/other/bin:$WORK/installed/bin:/usr/bin:/bin")" \
  || fail "install.sh's shadow check failed to run: $out"
case "$out" in *"is NOT the binary just installed"*) ;; *)
  fail "a shadowing varve did not produce a warning — the exact defect this gate exists for: $out" ;; esac
case "$out" in *"$WORK/other/bin/varve"*"varve 0.25.0"*) ;; *)
  fail "the warning does not name the winning binary and its version: $out" ;; esac
echo "   fired as required"

echo "== and must NOT fire when the install wins"
out="$(run_check "$WORK/installed/bin:$WORK/other/bin:/usr/bin:/bin")" \
  || fail "install.sh's shadow check failed to run: $out"
case "$out" in *"NOT the binary"*) fail "warned when the installed binary is the one that runs (false alarm): $out" ;; esac
echo "   quiet as required"

echo "== nor when nothing else is on PATH"
out="$(run_check "$WORK/installed/bin:/usr/bin:/bin")" \
  || fail "install.sh's shadow check failed to run: $out"
case "$out" in *"NOT the binary"*) fail "warned with no competing varve on PATH: $out" ;; esac
echo "   quiet as required"

echo "install-shadow systest: PASS — the installer names the winner, and the check can fail"
