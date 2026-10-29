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
# FAILS CLOSED: any other event, an empty base, a failed or empty diff, or any
# file that is not docs runs everything. "Docs" is narrow on purpose: a `.md`
# or LICENSE file OUTSIDE crates/ (crates/*/docs/*.md are include_str!'d into
# the binaries), whose basename no .rs, workflow or tools/ file mentions
# (README.md is include_str!'d by crates/varve/src/docs.rs).
set -uo pipefail
out="${GITHUB_OUTPUT:-/dev/stdout}"
run_all() { echo "code=true" >> "$out"; echo "-> $1; running everything"; exit 0; }

case "${EVENT_NAME:-}" in
  pull_request|merge_group) ;;
  *) run_all "event ${EVENT_NAME:-<none>}" ;;
esac
[ -n "${BASE_SHA:-}" ] || run_all "no base sha"
changed="$(git diff --name-only "$BASE_SHA"...HEAD)" || run_all "git diff failed against $BASE_SHA"
[ -n "$changed" ] || run_all "git diff returned no paths"
echo "changed files:"; echo "$changed"
while IFS= read -r f; do
  case "$f" in
    crates/*) run_all "$f is under crates/" ;;
    *.md|LICENSE|LICENSE-*) ;;
    *) run_all "non-docs file $f" ;;
  esac
  if git grep -qF -- "$(basename "$f")" -- '*.rs' '.github/workflows/*' 'tools/*'; then
    run_all "$f is referenced from source, a workflow or tools/"
  fi
done <<< "$changed"
echo "code=false" >> "$out"
echo "-> docs-only change; skipping the heavy jobs"
