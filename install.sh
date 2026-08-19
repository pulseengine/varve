#!/bin/sh
# varve installer — the first hop, and only the first hop.
#
# This script downloads one released varve binary and VERIFIES it against the
# release's SHA256SUMS.txt before anything is extracted or written. Every
# update after this one is `varve self-update`, which re-verifies with the
# running binary against the pinned trust root (old-verifies-new). This script
# deliberately does not reimplement that.
#
# From the v0.26.0 release onward this script is itself a release asset, so its
# own sha256 is in that release's signed SHA256SUMS.txt and you can verify this
# file before you run it. Earlier releases do NOT carry it — check the release's
# asset list rather than assuming. See the README, or `varve docs bootstrap`,
# for the verify-then-run form.
#
#   sh install.sh [--version <TAG>] [--dir <DIR>]
#
# Environment:
#   VARVE_VERSION      release tag to install (default: latest)
#   VARVE_INSTALL_DIR  where to put the binary (default: $HOME/.varve/bin)
#   VARVE_ALLOW_ROOT   set to 1 to permit running as root (default: refuse)

set -eu

REPO="pulseengine/varve"
RELEASES="https://github.com/${REPO}/releases"
VERSION="${VARVE_VERSION:-latest}"
INSTALL_DIR="${VARVE_INSTALL_DIR:-${HOME}/.varve/bin}"

say()  { printf '%s\n' "$*"; }
step() { printf '==> %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<'USAGE'
varve installer

  sh install.sh [--version <TAG>] [--dir <DIR>]

  --version <TAG>   release tag to install (e.g. v0.25.0); default: latest
  --dir <DIR>       install directory; default: $HOME/.varve/bin
  -h, --help        this message

Equivalent environment variables: VARVE_VERSION, VARVE_INSTALL_DIR.
Set VARVE_ALLOW_ROOT=1 to permit running as root (refused by default).
USAGE
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--version) [ "$#" -ge 2 ] || die "--version needs a tag"; VERSION="$2"; shift 2 ;;
		--dir)     [ "$#" -ge 2 ] || die "--dir needs a path";     INSTALL_DIR="$2"; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*)         usage >&2; die "unknown argument: $1" ;;
	esac
done

# ── Refuse to run as root ─────────────────────────────────────────────────
# A supply-chain tool that installs itself system-wide by accident is a bad
# default: varve is a per-user tool, and a root-owned binary on a shared PATH
# is a much larger blast radius than this script's job warrants.
if [ "$(id -u)" = "0" ] && [ "${VARVE_ALLOW_ROOT:-0}" != "1" ]; then
	die "refusing to run as root. varve installs per-user, into \$HOME/.varve/bin.
       If you really want a root-owned install, re-run with VARVE_ALLOW_ROOT=1
       and set VARVE_INSTALL_DIR to the destination you intend."
fi

# ── Detect the host, or refuse ────────────────────────────────────────────
# Guessing a triple is how you get a binary that segfaults or silently runs
# under emulation. varve names its four supported triples and stops.
detect_target() {
	os="$(uname -s)"
	arch="$(uname -m)"
	case "${os}/${arch}" in
		Darwin/arm64)                 echo "aarch64-apple-darwin" ;;
		Darwin/x86_64)                echo "x86_64-apple-darwin" ;;
		Linux/aarch64 | Linux/arm64)  echo "aarch64-unknown-linux-gnu" ;;
		Linux/x86_64 | Linux/amd64)   echo "x86_64-unknown-linux-gnu" ;;
		*)
			die "unsupported platform: ${os} ${arch}.
       varve publishes binaries for exactly these targets:
         aarch64-apple-darwin, x86_64-apple-darwin,
         aarch64-unknown-linux-gnu, x86_64-unknown-linux-gnu
       Build from source instead: cargo install varve
       (a source build is not covered by the release signature — see
        \`varve docs bootstrap\`)."
			;;
	esac
}

TARGET="$(detect_target)"

# ── Tools ─────────────────────────────────────────────────────────────────
if command -v curl >/dev/null 2>&1; then
	DOWNLOADER=curl
elif command -v wget >/dev/null 2>&1; then
	DOWNLOADER=wget
else
	die "neither curl nor wget is available; cannot download anything."
fi

# No sha256 tool means no verification, and an unverified install of a
# verification tool is worse than no install. Refuse rather than proceed.
if command -v sha256sum >/dev/null 2>&1; then
	sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
	sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
	die "no sha256 tool found (looked for sha256sum and shasum).
       Refusing to install unverified — install coreutils (sha256sum) or
       perl's shasum and re-run, or follow the manual verified path in
       \`varve docs bootstrap\`."
fi

fetch() { # fetch <url> <dest>
	case "$DOWNLOADER" in
		curl) curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1" ;;
		wget) wget -q -O "$2" "$1" ;;
	esac
}

fetch_stdout() { # fetch_stdout <url>
	case "$DOWNLOADER" in
		curl) curl -fsSL --proto '=https' --tlsv1.2 "$1" ;;
		wget) wget -q -O - "$1" ;;
	esac
}

# ── Resolve the tag ───────────────────────────────────────────────────────
# The archive name embeds the version, so "latest" has to become a real tag
# before any URL can be built.
resolve_latest() {
	if [ "$DOWNLOADER" = curl ]; then
		# The /releases/latest redirect names the tag; no API rate limit.
		effective="$(curl -fsSLI --proto '=https' --tlsv1.2 \
			-o /dev/null -w '%{url_effective}' "${RELEASES}/latest")"
		tag="${effective##*/}"
	else
		tag="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
			| tr ',' '\n' | grep '"tag_name"' | head -1 | cut -d'"' -f4)"
	fi
	case "$tag" in
		v*) echo "$tag" ;;
		*)  die "could not resolve the latest varve release tag (got '${tag}').
       Pass an explicit tag: sh install.sh --version v0.25.0" ;;
	esac
}

if [ "$VERSION" = "latest" ]; then
	step "Resolving the latest varve release"
	VERSION="$(resolve_latest)"
fi

ARCHIVE="varve-${VERSION}-${TARGET}.tar.gz"
ASSETS="${RELEASES}/download/${VERSION}"

say "varve ${VERSION}  (${TARGET})"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM HUP

# ── Download ──────────────────────────────────────────────────────────────
step "Downloading ${ARCHIVE}"
fetch "${ASSETS}/${ARCHIVE}" "${WORK}/${ARCHIVE}" \
	|| die "download failed: ${ASSETS}/${ARCHIVE}
       Check the tag exists and that this platform is published for it."

step "Downloading SHA256SUMS.txt"
fetch "${ASSETS}/SHA256SUMS.txt" "${WORK}/SHA256SUMS.txt" \
	|| die "download failed: ${ASSETS}/SHA256SUMS.txt — refusing to install unverified."

# ── Verify the archive BEFORE anything is extracted ───────────────────────
# The sums file lists names as `./<asset>`; match the whole field, never a
# substring, so one asset name cannot stand in for another.
expected="$(awk -v want="$ARCHIVE" '
	{ name = $2; sub(/^\.\//, "", name); sub(/^\*/, "", name)
	  if (name == want) { print $1; exit } }
' "${WORK}/SHA256SUMS.txt")"

[ -n "$expected" ] \
	|| die "SHA256SUMS.txt for ${VERSION} has no entry for ${ARCHIVE} — refusing to install."

actual="$(sha256_of "${WORK}/${ARCHIVE}")"

if [ "$actual" != "$expected" ]; then
	die "checksum mismatch for ${ARCHIVE} — NOT installing.
         expected: ${expected}
         actual:   ${actual}
       The bytes you received are not the bytes this release published.
       Do not run them. Report this at ${RELEASES}."
fi
step "sha256 verified against SHA256SUMS.txt"
say "    ${actual}"

# ── Verify SHA256SUMS.txt itself, when cosign is available ────────────────
# The checksum above proves the archive matches the sums file. It says nothing
# about who wrote the sums file. cosign closes that; without it, say so plainly
# rather than letting the user believe the install was signature-checked.
COSIGN_IDENTITY='^https://github\.com/pulseengine/varve/\.github/workflows/release\.yml@'
COSIGN_ISSUER='https://token.actions.githubusercontent.com'

if command -v cosign >/dev/null 2>&1; then
	step "Verifying SHA256SUMS.txt signature with cosign"
	fetch "${ASSETS}/SHA256SUMS.txt.cosign.bundle" "${WORK}/SHA256SUMS.txt.cosign.bundle" \
		|| die "cosign is installed but the signature bundle could not be downloaded — refusing."
	cosign verify-blob \
		--bundle "${WORK}/SHA256SUMS.txt.cosign.bundle" \
		--certificate-identity-regexp "$COSIGN_IDENTITY" \
		--certificate-oidc-issuer "$COSIGN_ISSUER" \
		"${WORK}/SHA256SUMS.txt" \
		|| die "cosign could not verify SHA256SUMS.txt — NOT installing."
	step "signature verified: SHA256SUMS.txt was produced by ${REPO}'s release workflow"
	SIGNATURE_CHECKED=yes
else
	SIGNATURE_CHECKED=no
fi

# ── Install ───────────────────────────────────────────────────────────────
step "Extracting"
mkdir -p "${WORK}/unpack"
tar -xzf "${WORK}/${ARCHIVE}" -C "${WORK}/unpack"
[ -f "${WORK}/unpack/varve" ] || die "the archive does not contain a 'varve' binary."

mkdir -p "$INSTALL_DIR"
cp "${WORK}/unpack/varve" "${INSTALL_DIR}/varve.new"
chmod 0755 "${INSTALL_DIR}/varve.new"
mv "${INSTALL_DIR}/varve.new" "${INSTALL_DIR}/varve"

installed="$("${INSTALL_DIR}/varve" --version)" \
	|| die "the installed binary does not run: ${INSTALL_DIR}/varve"
step "Installed ${installed} to ${INSTALL_DIR}/varve"

# ── What the user has, and what they do not ───────────────────────────────
say ""
if [ "$SIGNATURE_CHECKED" = no ]; then
	say "NOTE: the SIGNATURE was NOT checked. cosign is not installed, so this"
	say "      install verified integrity (sha256 against SHA256SUMS.txt) but not"
	say "      authorship. To check it now:"
	say ""
	say "        cosign verify-blob \\"
	say "          --bundle SHA256SUMS.txt.cosign.bundle \\"
	say "          --certificate-identity-regexp '${COSIGN_IDENTITY}' \\"
	say "          --certificate-oidc-issuer ${COSIGN_ISSUER} \\"
	say "          SHA256SUMS.txt"
	say ""
	say "      (download both from ${ASSETS})"
	say ""
fi

case ":${PATH}:" in
	*":${INSTALL_DIR}:"*)
		say "${INSTALL_DIR} is already on PATH."
		;;
	*)
		say "Add it to PATH:"
		say ""
		say "    export PATH=\"${INSTALL_DIR}:\$PATH\""
		say ""
		say "…and put that line in your shell profile (~/.profile, ~/.zshrc, …)."
		;;
esac

say ""
say "Next:"
say "    varve docs getting-started   # pin a layer and dispatch its tools"
say "    varve docs bootstrap         # what this script verified, and what it did not"
say "    varve self-update            # every update after this one; re-verified"
say "                                 # by the running binary against the trust root"
