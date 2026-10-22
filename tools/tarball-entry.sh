# shellcheck shell=bash
# The shape of one TARBALL_TOOLS entry, decided in ONE place.
#
#   [owner/]tool : version [: binary [: asset-template [: payload-version]]]
#
# Sourced by tools/build-deposit-spec.sh (the deposit) and by
# tools/systest/deposit-layer.sh (the live-pin check), so the two cannot
# disagree about what an entry is. They did (varve#267): an edit in #266
# dropped the space between two entries, producing
#
#   kiln:v0.6.0:kilndpulseengine/varve:v0.32.0:varve-producer:varve-producer-v%V-%T.tar.gz
#
# The deposit would have lost the varve-producer payload and asked the kiln
# archive for a binary named `kilndpulseengine/varve`; the systest read only the
# first two fields, saw a valid `kiln v0.6.0`, and passed.

# Print why ENTRY is malformed, or nothing if it is well formed.
tarball_entry_fault() {
  local entry="$1" fields
  fields="$(printf '%s' "$entry" | awk -F: '{print NF}')"
  if [ "$fields" -lt 2 ]; then
    echo "has no ':version' — an entry names at least a tool and a version"
    return
  fi
  if [ "$fields" -gt 5 ]; then
    echo "has $fields ':'-separated fields; an entry has at most 5 — two entries fused by a missing space look exactly like this"
    return
  fi
  local tool version binary template payload
  IFS=':' read -r tool version binary template payload <<ENTRYEOF
$entry
ENTRYEOF
  case "$tool" in
    */*/*|/*|*/) echo "names '$tool', which is not [owner/]tool"; return ;;
  esac
  printf '%s' "${tool##*/}" | grep -Eq '^[A-Za-z0-9._-]+$' \
    || { echo "names tool '$tool', which is not a plain name"; return; }
  # A whole version, not one that merely STARTS like one: fusing
  # `rivet:v0.35.0` and `spar:v0.40.0` gives version `v0.35.0spar`, which a
  # starts-with-a-digit check accepted (found by this file's own negative
  # control in tools/systest/deposit-layer.sh).
  printf '%s' "$version" | grep -Eq '^v?[0-9]+(\.[0-9]+)*([-+][0-9A-Za-z.-]+)?$' \
    || { echo "has version '$version', which is not a version — two entries fused by a missing space look like this"; return; }
  if [ -n "$binary" ]; then
    printf '%s' "$binary" | grep -Eq '^[A-Za-z0-9._-]+$' \
      || { echo "names binary '$binary', which is not a plain file name"; return; }
  fi
  if [ -n "$template" ]; then
    case "$template" in
      *%T*|*%U*) ;;
      *) echo "has asset template '$template' with neither %T nor %U, so every platform would fetch one file"; return ;;
    esac
  fi
  if [ -n "$payload" ]; then
    printf '%s' "$payload" | grep -Eq '^[0-9][0-9A-Za-z.+-]*$' \
      || { echo "has payload version '$payload', which is not a version"; return; }
  fi
}
