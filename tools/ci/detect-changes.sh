#!/usr/bin/env bash
# Changed-area detector for ci.yml and systest.yml.
#
# Writes code=true|false to $GITHUB_OUTPUT. code=false means the change is
# docs-only, and the heavy jobs skip by job-level `if:` (a job skipped that way
# still reports, so its required context is satisfied; a workflow skipped by
# `paths:` reports nothing and would hang the merge queue).
#
# Inputs (env): EVENT_NAME, BASE_SHA. pull_request passes the PR base;
# merge_group passes merge_group.base_sha (the checkout is the queue commit, so
# base...HEAD is what that entry adds).
#
# FAILS CLOSED: any other event, an empty base, a failed or empty diff, a
# failed `git grep`, or any file that is not docs runs everything. "Docs" is
# narrow on purpose: a `.md` or LICENSE file OUTSIDE crates/
# (crates/*/docs/*.md are include_str!'d into the binaries), whose basename
# no .rs, workflow or tools/ file mentions (README.md is include_str!'d by
# crates/varve/src/docs.rs).
set -uo pipefail
out="${GITHUB_OUTPUT:-/dev/stdout}"
run_all() { echo "code=true" >> "$out"; echo "-> $1; running everything"; exit 0; }

# temper's gate probe (temper docs/gate-probe.md, .github/gate-probe.json)
# hands the changed paths in GATE_PROBE_FILES, one per line, with no other
# environment. Read them BEFORE the event check: with no EVENT_NAME the event
# check runs everything, so a probe that reached it would pass without testing
# the classification at all.
if [ -n "${GATE_PROBE_FILES:-}" ]; then
  [ -r "$GATE_PROBE_FILES" ] || run_all "GATE_PROBE_FILES $GATE_PROBE_FILES is not readable"
  changed="$(grep -v '^[[:space:]]*$' "$GATE_PROBE_FILES")" || changed=""
else
  case "${EVENT_NAME:-}" in
    pull_request|merge_group) ;;
    *) run_all "event ${EVENT_NAME:-<none>}" ;;
  esac
  [ -n "${BASE_SHA:-}" ] || run_all "no base sha"
  changed="$(git diff --name-only "$BASE_SHA"...HEAD)" || run_all "git diff failed against $BASE_SHA"
fi
[ -n "$changed" ] || run_all "git diff returned no paths"
echo "changed files:"; echo "$changed"
while IFS= read -r f; do
  case "$f" in
    crates/*) run_all "$f is under crates/" ;;
    *.md|LICENSE|LICENSE-*) ;;
    *) run_all "non-docs file $f" ;;
  esac
  # 0 = referenced, 1 = not referenced; anything else is an error and fails
  # closed (#352: exit 128 outside a repository read as "not referenced").
  git grep -qF -- "$(basename "$f")" -- '*.rs' '.github/workflows/*' 'tools/*'
  rc=$?
  case "$rc" in
    0) run_all "$f is referenced from source, a workflow or tools/" ;;
    1) ;;
    *) run_all "git grep failed (exit $rc) while checking $f" ;;
  esac
done <<< "$changed"
echo "code=false" >> "$out"
echo "-> docs-only change; skipping the heavy jobs"
