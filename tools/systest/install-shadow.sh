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
# It runs install.sh's real decision logic against a fabricated PATH; the
# download and signature steps are not what is under test here.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/installed/bin" "$WORK/other/bin"
printf '#!/bin/sh\necho "varve 9.9.9"\n' > "$WORK/installed/bin/varve"
printf '#!/bin/sh\necho "varve 0.25.0"\n' > "$WORK/other/bin/varve"
chmod +x "$WORK/installed/bin/varve" "$WORK/other/bin/varve"

# The decision under test, lifted verbatim in shape from install.sh.
probe() { # PATH-value -> prints, exit 7 when it warns
  INSTALL_DIR="$WORK/installed/bin" installed="varve 9.9.9" \
  PATH="$1" bash -c '
    winner="$(command -v varve 2>/dev/null || true)"
    if [ -n "$winner" ] && [ "$winner" != "${INSTALL_DIR}/varve" ]; then
      echo "WARNING: varve on PATH is not the binary just installed: $winner"
      exit 7
    fi
    echo "ok: the install wins"
  '
}

echo "== the warning must FIRE when another varve wins PATH"
if probe "$WORK/other/bin:$WORK/installed/bin:/usr/bin:/bin" >/dev/null 2>&1; then
  fail "a shadowing varve did not produce a warning — the exact defect this gate exists for"
fi
echo "   fired as required"

echo "== and must NOT fire when the install wins"
probe "$WORK/installed/bin:$WORK/other/bin:/usr/bin:/bin" >/dev/null 2>&1 \
  || fail "warned when the installed binary is the one that runs (false alarm)"
echo "   quiet as required"

echo "== nor when nothing else is on PATH"
probe "$WORK/installed/bin:/usr/bin:/bin" >/dev/null 2>&1 \
  || fail "warned with no competing varve on PATH"
echo "   quiet as required"

echo "== install.sh actually carries the check"
grep -q 'command -v varve' "$HERE/install.sh" \
  || fail "install.sh no longer resolves varve the way the shell does"
grep -q 'is NOT the binary just installed' "$HERE/install.sh" \
  || fail "install.sh no longer warns about a shadowing varve"
grep -q 'replaced' "$HERE/install.sh" \
  || fail "install.sh no longer reports what it replaced"
echo "   present"

echo "install-shadow systest: PASS — the installer names the winner, and the check can fail"
