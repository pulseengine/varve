#!/usr/bin/env bash
# REQ-NOKEYDISK-001: no varve-operated workflow may write key material to a file.
#
# `docs ci` tells adopters that "every adopter therefore invents
# `echo "$SECRET" > key.tmp`, which leaves the realm's one secret on disk", and
# `docs root-ceremony` says the key must reach varve "through a file
# descriptor, never a workspace file". varve's own deposit workflow wrote it to
# a predictable /tmp path on a shared runner for every layer it ever published.
#
# An assessor found that by reading the repository rather than the
# documentation, and was right that it is the finding which invalidates every
# other procedural claim by induction: a published procedure the publisher does
# not follow is not evidence of anything.
#
# So the rule is mechanical from here. This refuses a redirect of anything
# key-shaped into a file. It is deliberately about the SHAPE of the line, not
# about whether a human reviewer noticed.
#
# Usage:  tools/no-key-on-disk.sh [dir]        (default .github/workflows)
set -euo pipefail

# --self-test: prove this gate can go RED before trusting it green.
#
# A gate admitted without a proof that it can fail is not a gate, and this
# repository has found that class of defect repeatedly -- including in this very
# script, which on its first run flagged its own documentation comment. The
# controls below include the EXACT line this repository shipped for every layer
# it published, so a future refactor that guts the pattern fails here rather
# than silently allowing the thing back.
# rivet: verifies REQ-NOKEYDISK-001
if [ "${1:-}" = "--self-test" ]; then
  work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
  mkdir -p "$work/wf"
  fail=0
  must_reject() { # name, line
    printf 'jobs:\n  x:\n    steps:\n      - run: %s\n' "$2" > "$work/wf/a.yml"
    if "$0" "$work/wf" >/dev/null 2>&1; then
      echo "::error::self-test: gate ACCEPTED what it must reject ($1): $2"; fail=1
    else
      echo "  rejects: $1"
    fi
  }
  must_accept() { # name, line
    printf 'jobs:\n  x:\n    steps:\n      - run: %s\n' "$2" > "$work/wf/a.yml"
    if "$0" "$work/wf" >/dev/null 2>&1; then
      echo "  accepts: $1"
    else
      echo "::error::self-test: gate REJECTED what it must accept ($1): $2"; fail=1
    fi
  }
  # The line this repository actually shipped, verbatim.
  must_reject "the pattern varve shipped"  "printf '%s' \"\$VARVE_ROLLING_KEY\" > /tmp/rolling.key"
  must_reject "the adopter mistake docs name" 'echo "$SIGNING_SECRET" > key.tmp'
  must_reject "append"                     'printf %s "$VARVE_ROOT_KEY" >> /tmp/k'
  must_reject "tee"                        'printf %s "$MY_TOKEN" | tee /tmp/t'
  must_accept "the documented fd form"     "varve deposit --key <(printf '%s' \"\$VARVE_ROLLING_KEY\") --out o"
  must_accept "a pipe to /dev/stdin"       "printf '%s' \"\$K\" | varve sign-status --key /dev/stdin"
  [ "$fail" -eq 0 ] || { echo "::error::no-key-on-disk self-test FAILED"; exit 1; }
  echo "no-key-on-disk: self-test OK — the gate rejects 4 shapes and accepts 2"
  exit 0
fi

DIR="${1:-.github/workflows}"

# A secret-looking variable redirected into a file. Covers `> f`, `>> f`, and
# `tee f`, with or without quotes around the variable.
PATTERN='(\$\{?[A-Za-z_]*(KEY|SECRET|TOKEN)[A-Za-z_]*\}?"?[[:space:]]*(>>?|\|[[:space:]]*tee)[[:space:]])|((>>?|\|[[:space:]]*tee)[[:space:]]*[^[:space:]|]*(key|secret)[^[:space:]|]*$)'

found=0
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  echo "::error::$hit"
  found=1
# Comments are stripped BEFORE matching, not after: grep -rIn prefixes each hit
# with `file:line:`, so a naive `grep -v '^#'` never sees a commented line --
# which this script proved on its first run by flagging its own documentation.
done < <(grep -rInE "$PATTERN" "$DIR" 2>/dev/null \
         | awk -F: '{ rest = substr($0, index($0, $3)); sub(/^[[:space:]]+/, "", rest);
                      if (rest !~ /^#/) print }' || true)

if [ "$found" -ne 0 ]; then
  cat >&2 <<'WHY'

REQ-NOKEYDISK-001: a signing key must not be written to a filesystem path.
Use the file-descriptor forms `varve docs ci` documents:

    varve deposit --key <(printf '%s' "$VARVE_SIGNING_KEY") ...
    printf '%s' "$VARVE_SIGNING_KEY" | varve sign-status --key /dev/stdin ...

A short-lived `mktemp` file is acceptable for a THROWAWAY key and for nothing
that a realm's consumers pin.
WHY
  exit 1
fi
echo "no-key-on-disk: OK — no workflow writes key material to a file"
