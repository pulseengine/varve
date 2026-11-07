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
# Two layers, because each alone leaves a hole (#333, item 1):
#
#   1. install.sh's OWN check_shadow (via VARVE_INSTALL_SHADOW_CHECK_ONLY=1)
#      against a fabricated PATH, so changing the real condition changes this
#      gate's verdict. That does not prove the installer CALLS it: replacing
#      the call site with `:` left this gate green.
#   2. install.sh's NORMAL path, end to end, against a fake `curl` that serves
#      a local archive and its sums. The installer downloads, verifies and
#      installs, and the gate asserts the warning in ITS output, with no hook.
#      Removing the real call now goes red.
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

# ── Layer 2: the installer's normal path, no check-only hook ───────────────
# A fake curl stands in for the network. install.sh calls it as
# `curl ... -o <dest> <url>` and, with a pinned --version, nothing else.
FIX="$WORK/fixture"; FAKEBIN="$WORK/fakebin"
mkdir -p "$FIX/pkg" "$FAKEBIN"
printf '#!/bin/sh\necho "varve 9.9.9"\n' > "$FIX/pkg/varve"
chmod +x "$FIX/pkg/varve"
tar -czf "$FIX/archive.tar.gz" -C "$FIX/pkg" varve
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$FIX/archive.tar.gz" | awk '{print $1}' > "$FIX/sum"
else
  shasum -a 256 "$FIX/archive.tar.gz" | awk '{print $1}' > "$FIX/sum"
fi
cat > "$FAKEBIN/curl" <<'FAKE'
#!/bin/sh
dest=""
while [ "$#" -gt 1 ]; do
  case "$1" in -o) dest="$2"; shift 2 ;; *) shift ;; esac
done
url="$1"
case "$url" in
  */SHA256SUMS.txt) printf '%s  ./%s\n' "$(cat "$FIXTURE/sum")" "$(cat "$FIXTURE/name")" > "$dest" ;;
  */*.tar.gz) basename "$url" > "$FIXTURE/name"; cp "$FIXTURE/archive.tar.gz" "$dest" ;;
  *) echo "fake curl: unexpected url $url" >&2; exit 22 ;;
esac
FAKE
chmod +x "$FAKEBIN/curl"

# Run the installer's normal path with PATH set to $1; prints its output.
run_install() {
  rm -rf "$WORK/inst"
  FIXTURE="$FIX" VARVE_ALLOW_ROOT=1 VARVE_INSTALL_DIR="$WORK/inst/bin" \
    PATH="$FAKEBIN:$1" sh "$HERE/install.sh" --version v9.9.9 2>&1
}

# rivet: verifies REQ-INSTALLSHADOW-001
echo "== the installer's own run must warn, with no check-only hook, when another varve wins PATH"
out="$(run_install "$WORK/other/bin:$WORK/inst/bin:/usr/bin:/bin")" \
  || fail "the installer's normal path failed against the fixture: $out"
case "$out" in *"Installed varve 9.9.9"*) ;; *)
  fail "the installer did not complete the install, so the call site was not reached: $out" ;; esac
case "$out" in *"is NOT the binary just installed"*) ;; *)
  fail "install.sh installed and said nothing about the varve that shadows it — its call to check_shadow is gone or inert: $out" ;; esac
echo "   the installer warned on its own"

echo "== and its own run stays quiet when the install wins"
out="$(run_install "$WORK/inst/bin:$WORK/other/bin:/usr/bin:/bin")" \
  || fail "the installer's normal path failed against the fixture: $out"
case "$out" in *"NOT the binary"*) fail "the installer warned when its own binary wins PATH: $out" ;; esac
echo "   quiet as required"

echo "install-shadow systest: PASS — the installer names the winner, and the check can fail"
