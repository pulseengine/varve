#!/usr/bin/env bash
# Notice that upstream moved, and propose the layer — REQ-ROLLING-001.
#
# The problem this exists for, measured. Days after layer 2026.08.3 was
# published, rivet had gone v0.33.1 -> v0.34.0, spar v0.36.0 -> v0.40.0 (FOUR
# minors), synth v0.55.0 -> v0.58.0, witness v0.39.0 -> v0.43.0, ordeal
# v0.18.0 -> v0.19.0. A consumer pinned to the rolling channel was not getting
# a rolling toolchain; they were getting whatever happened to be current the
# last time a human remembered to cut a layer.
#
# The obvious fix — scan, assemble, sign and publish on a timer — is the wrong
# one, and this script deliberately does not do it (DD-024). In varve,
# channel = "rolling" is NOT a trust boundary: a rolling layer is signed by the
# SAME realm root as a qualified one, and the realm is the boundary. Publishing
# on a timer therefore means the realm root signs unattended, dozens of times a
# week, while `varve docs root-ceremony` tells operators to use that key as
# rarely as possible, air-gapped, under a two-person rule, with every use
# recorded as a ceremony entry. varve has neither revocation nor rotation: a
# layer published in error cannot be withdrawn.
#
# So this automates the TOIL and leaves the JUDGEMENT: it notices, it diffs, it
# checks who vouches for each new artifact, and it opens a PULL REQUEST
# carrying the version diff. It never deposits, never signs and never
# publishes. A human merging that PR is what triggers the signed deposit, so
# every signature stays an act a person took.
#
# Usage:
#   tools/scan-upstream.sh scan    [--workflow F] [--out DIR]
#   tools/scan-upstream.sh propose [--out DIR] [--apply] [--branch B]
#                                  [--gate pass|fail|skipped] [--gate-url URL]
#
# `scan` is read-only against the GitHub API and writes a proposal into DIR.
# `propose` turns that proposal into a branch and a PR — but ONLY with
# --apply (or VARVE_SCAN_APPLY=1). Without it every mutating step is printed
# and not run, which is the default precisely so that running this by hand
# cannot open a PR by accident.
#
# Outputs under DIR:
#   status            one word: moved | unchanged | blocked-only
#   resolved.tsv      one row per repo: what it was, what it is, who vouched
#   deposit-layer.yml.proposed   the workflow file with the pins bumped
#   pins.diff         the diff a reader of the PR will see
#   pr-body.md        the proposal, in prose and a table
#   pr-title.txt
#
# External programs: `gh`, `jq`, `python3`, and `cosign` (via
# tools/upstream-mechanism.sh) are taken from PATH — the same seam the deposit
# assembler uses, so a system test can back them with fixtures.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# shellcheck source=tools/upstream-mechanism.sh
. "$HERE/upstream-mechanism.sh"

CMD="${1:-}"; shift || true
WORKFLOW="$REPO_ROOT/.github/workflows/deposit-layer.yml"
OUT=""
APPLY="${VARVE_SCAN_APPLY:-0}"
BRANCH="${VARVE_SCAN_BRANCH:-rolling/upstream-scan}"
BASE="${VARVE_SCAN_BASE:-main}"
GATE="skipped"
GATE_URL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --workflow) WORKFLOW="$2"; shift 2 ;;
    --out)      OUT="$2"; shift 2 ;;
    --branch)   BRANCH="$2"; shift 2 ;;
    --base)     BASE="$2"; shift 2 ;;
    --gate)     GATE="$2"; shift 2 ;;
    --gate-url) GATE_URL="$2"; shift 2 ;;
    --apply)    APPLY=1; shift ;;
    -h|--help)  sed -n '2,50p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "$CMD" != pins ]; then
  : "${OUT:?--out DIR is required}"
  mkdir -p "$OUT"
  OUT="$(cd "$OUT" && pwd)"
fi

TAB="$(printf '\t')"
die() { echo "::error::$*" >&2; exit 1; }

# ── version arithmetic ───────────────────────────────────────────────────────
# Dot-separated numerics only; anything else was filtered out before it got
# here. Pure bash because macOS ships bash 3.2 and a gate you cannot run on
# your own machine is a gate you will not run before pushing.
ver_cmp() { # a b -> -1 | 0 | 1
  local a="${1#v}" b="${2#v}" i ai bi
  local -a A B
  IFS=. read -r -a A <<< "$a"
  IFS=. read -r -a B <<< "$b"
  for i in 0 1 2 3; do
    ai="${A[$i]:-0}"; bi="${B[$i]:-0}"
    ai=$((10#$ai)); bi=$((10#$bi))
    if [ "$ai" -gt "$bi" ]; then echo 1; return; fi
    if [ "$ai" -lt "$bi" ]; then echo -1; return; fi
  done
  echo 0
}

bump_kind() { # from to -> major | minor | patch
  local a="${1#v}" b="${2#v}"
  local -a A B
  IFS=. read -r -a A <<< "$a"
  IFS=. read -r -a B <<< "$b"
  if [ "$((10#${A[0]:-0}))" != "$((10#${B[0]:-0}))" ]; then echo major; return; fi
  if [ "$((10#${A[1]:-0}))" != "$((10#${B[1]:-0}))" ]; then echo minor; return; fi
  echo patch
}

# ── the workflow's env block is the source of truth for the layer contents ───
# Read, never written by hand here: the PR is the only thing that changes it,
# which is what keeps the pins a reviewed diff.
wf_env() { sed -n "s/^  $1: //p" "$WORKFLOW" | head -1 | sed 's/^"//; s/"$//'; }

# TARBALL_TOOLS entries name a tool; the assembler maps that to
# pulseengine/<tool>. An entry that already spells owner/name is passed
# through, so a non-pulseengine upstream needs no change here — see the report
# note about the assembler's own repo rule.
entry_repo() { case "$1" in */*) echo "$1" ;; *) echo "pulseengine/$1" ;; esac; }

scan() {
  [ -f "$WORKFLOW" ] || die "no such workflow: $WORKFLOW"
  local tarball wsc vsix
  tarball="$(wf_env TARBALL_TOOLS)"
  wsc="$(wf_env WSC_VERSION)"
  vsix="$(wf_env VSIX_PACKAGES)"
  { [ -n "$tarball" ] && [ -n "$wsc" ] && [ -n "$vsix" ]; } \
    || die "could not read TARBALL_TOOLS/WSC_VERSION/VSIX_PACKAGES out of $WORKFLOW — \
the scanner must fail loudly here, because reading nothing looks exactly like nothing having moved"

  # ── 1. the pin table ───────────────────────────────────────────────────────
  # Keyed by REPO, not by list entry. rivet and spar each appear in both
  # TARBALL_TOOLS and VSIX_PACKAGES (a CLI and a VS Code extension cut from one
  # release), and one release per repo per layer is a hard rule of the
  # assembler: two entries at two versions would check one release's assets
  # against the other's sums. Resolving per repo makes a bump land in both
  # places or in neither.
  local pins="$OUT/pins.tsv"; : > "$pins"
  local entry tool rest version repo
  for entry in $tarball; do
    tool="${entry%%:*}"; rest="${entry#*:}"; version="${rest%%:*}"
    repo="$(entry_repo "$tool")"
    printf '%s\t%s\t%s\tTARBALL_TOOLS\n' "$repo" "$version" "$tool" >> "$pins"
  done
  printf '%s\t%s\t%s\tWSC_VERSION\n' pulseengine/sigil "$wsc" wsc >> "$pins"
  for entry in $vsix; do
    tool="${entry%%:*}"; rest="${entry#*:}"; version="${rest%%:*}"
    repo="$(entry_repo "$tool")"
    printf '%s\t%s\t%s\tVSIX_PACKAGES\n' "$repo" "$version" "$tool" >> "$pins"
  done

  local repos; repos="$(cut -f1 "$pins" | sort -u)"
  local skew; skew="$(cut -f1,2 "$pins" | sort -u | cut -f1 | uniq -d)"
  [ -z "$skew" ] || die "the shipping layer already names a repo at two versions ($skew) — \
refusing to propose on top of a pin set the deposit would reject"

  echo "== scanning $(printf '%s\n' "$repos" | wc -l | tr -d ' ') upstream repos named by $WORKFLOW"

  # ── 2. what is upstream now ────────────────────────────────────────────────
  mkdir -p "$OUT/releases" "$OUT/probe"
  local resolved="$OUT/resolved.tsv"; : > "$resolved"
  local moved=0 blocked=0
  local cur safe rels tags tag best skipped kind mech detail rc

  for repo in $repos; do
    cur="$(grep "^$repo$TAB" "$pins" | cut -f2 | head -1)"
    safe="${repo//\//_}"
    rels="$OUT/releases/$safe.json"
    # One API call per repo. Read-only: this endpoint lists releases and
    # nothing else, which is why the scan needs no elevated token.
    gh api "/repos/$repo/releases?per_page=100" > "$rels" 2>"$OUT/releases/$safe.err" || {
      echo "::warning::could not list releases for $repo — holding its pin at $cur"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$repo" "$cur" "$cur" hold - 0 "release listing failed: $(head -1 "$OUT/releases/$safe.err")" >> "$resolved"
      continue
    }
    # Drafts and prereleases are not candidates: a layer is what a consumer
    # gets by default. Tags that are not plain dotted numerics are skipped
    # rather than guessed at.
    tags="$(jq -r '.[]
                   | select(.draft | not)
                   | select(.prerelease | not)
                   | select(.tag_name | test("^v?[0-9]+(\\.[0-9]+){0,3}$"))
                   | .tag_name' "$rels")"
    best=""
    for tag in $tags; do
      if [ -z "$best" ] || [ "$(ver_cmp "$tag" "$best")" = 1 ]; then best="$tag"; fi
    done
    if [ -z "$best" ]; then
      echo "::warning::$repo publishes no plain versioned release — holding at $cur"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$repo" "$cur" "$cur" hold - 0 "no plain versioned release found" >> "$resolved"
      continue
    fi

    case "$(ver_cmp "$best" "$cur")" in
      0)
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$repo" "$cur" "$cur" current - 0 "already at the latest release" >> "$resolved"
        continue ;;
      -1)
        # The pin is AHEAD of anything published — a deleted or yanked release
        # upstream. Never propose a downgrade; say so and hold.
        echo "::warning::$repo is pinned at $cur but the newest published release is $best — holding"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
          "$repo" "$cur" "$cur" hold - 0 "pin is ahead of the newest published release ($best)" >> "$resolved"
        continue ;;
    esac

    # How far it moved, and how many releases went by unnoticed — the number
    # that says whether a weekly cadence is keeping up.
    skipped=0
    for tag in $tags; do
      [ "$(ver_cmp "$tag" "$cur")" = 1 ] && skipped=$((skipped+1))
    done
    kind="$(bump_kind "$cur" "$best")"

    # ── 3. who vouches for it ────────────────────────────────────────────────
    # Clause 5: an upstream we cannot verify blocks THAT tool, not the whole
    # proposal. Seven verified bumps must not be frozen by one unattested
    # eighth — that is how a rolling channel stops rolling.
    jq --arg t "$best" '.[] | select(.tag_name == $t)' "$rels" > "$OUT/probe/$safe.release.json"
    rc=0
    mech="$(upstream_mechanism "$repo" "$best" "$OUT/probe/$safe.release.json" "$OUT/probe")" || rc=$?
    if [ "$rc" = 2 ]; then exit 1; fi
    if [ "$rc" != 0 ]; then
      echo "   $repo $cur -> $best: BLOCKED — nothing vouches for it ($UPSTREAM_MECHANISMS all declined)"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$repo" "$cur" "$best" blocked - "$skipped" \
        "no mechanism vouched (tried: $UPSTREAM_MECHANISMS) — pin held at $cur" >> "$resolved"
      blocked=$((blocked+1))
      continue
    fi
    detail="${mech#*$TAB}"; mech="${mech%%$TAB*}"
    echo "   $repo $cur -> $best ($kind, $skipped release(s)) — vouched by $mech"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$repo" "$cur" "$best" move "$mech" "$skipped" "$detail" >> "$resolved"
    moved=$((moved+1))
  done

  # ── 4. the verdict ─────────────────────────────────────────────────────────
  # Clause 6: silence when nothing moved. A scheduled task that reports every
  # time it runs is a scheduled task people build a filter for, and the one
  # message that mattered goes into the same folder as the other ninety-nine.
  if [ "$moved" = 0 ]; then
    if [ "$blocked" = 0 ]; then
      printf 'unchanged\n' > "$OUT/status"
      echo "== nothing moved — no proposal, no PR, no notification"
    else
      # Something moved but nothing verifiable moved. There is no diff to
      # propose, so there is no PR; the log carries the reason so it is
      # visible to whoever goes looking, without nagging weekly about an
      # upstream that may never sign.
      printf 'blocked-only\n' > "$OUT/status"
      echo "::notice::$blocked upstream release(s) moved but none could be vouched for — no proposal"
    fi
    emit_gh_output "$(cat "$OUT/status")"
    return 0
  fi

  printf 'moved\n' > "$OUT/status"

  # ── 5. the proposal ────────────────────────────────────────────────────────
  rewrite_workflow "$resolved"
  diff -u "$WORKFLOW" "$OUT/deposit-layer.yml.proposed" > "$OUT/pins.diff" || true
  write_pr_text "$resolved" "$moved" "$blocked"
  echo "== proposal written to $OUT (status: moved)"
  emit_gh_output moved
}

emit_gh_output() {
  [ -n "${GITHUB_OUTPUT:-}" ] || return 0
  {
    printf 'status=%s\n' "$1"
    printf 'moved=%s\n' "$([ "$1" = moved ] && echo true || echo false)"
  } >> "$GITHUB_OUTPUT"
}

# Rewrite the three env values in place. Only the version field of each entry
# changes; the entry SHAPE — the optional binary name, the vsix extension name
# and asset template with their %V/%P placeholders — is preserved exactly,
# because those encode facts about the release that no scan can rediscover.
rewrite_workflow() { # resolved.tsv
  python3 - "$WORKFLOW" "$1" "$OUT/deposit-layer.yml.proposed" <<'PY'
import sys

wf, resolved, out = sys.argv[1], sys.argv[2], sys.argv[3]

new = {}
for line in open(resolved):
    repo, cur, latest, decision, mech, skipped, detail = line.rstrip('\n').split('\t')
    if decision == 'move':
        new[repo] = latest

def repo_of(tool):
    return tool if '/' in tool else 'pulseengine/' + tool

# Both lists are colon-separated with the version SECOND, and both are checked
# against their documented arity: a reshaped env block must stop this rewrite
# rather than have version numbers written into whatever field now sits there.
def bump_tarball(value):
    out = []
    for e in value.split():
        parts = e.split(':')
        if len(parts) not in (2, 3):
            sys.exit('::error::TARBALL_TOOLS entry %r is not tool:version[:binary]' % e)
        parts[1] = new.get(repo_of(parts[0]), parts[1])
        out.append(':'.join(parts))
    return ' '.join(out)

def bump_vsix(value):
    out = []
    for e in value.split():
        parts = e.split(':')
        if len(parts) != 4:
            sys.exit('::error::VSIX_PACKAGES entry %r is not repo:version:extension:asset-template' % e)
        parts[1] = new.get(repo_of(parts[0]), parts[1])
        out.append(':'.join(parts))
    return ' '.join(out)

def bump_wsc(value):
    return new.get('pulseengine/sigil', value)

handlers = {
    'TARBALL_TOOLS': bump_tarball,
    'VSIX_PACKAGES': bump_vsix,
    'WSC_VERSION': bump_wsc,
}

lines = open(wf).read().split('\n')
seen = set()
for i, line in enumerate(lines):
    for key, fn in handlers.items():
        prefix = '  %s: ' % key
        if not line.startswith(prefix) or key in seen:
            continue
        seen.add(key)
        raw = line[len(prefix):]
        quoted = raw.startswith('"') and raw.endswith('"')
        value = raw[1:-1] if quoted else raw
        bumped = fn(value)
        lines[i] = prefix + ('"%s"' % bumped if quoted else bumped)

missing = set(handlers) - seen
if missing:
    sys.exit('::error::env keys not found in %s: %s' % (wf, ', '.join(sorted(missing))))

open(out, 'w').write('\n'.join(lines))
PY
}

# Clause 4: the PR shows what actually changed — which tools moved, by how
# much, and which ingestion mechanism vouched for each new artifact. A diff of
# eight version strings tells a reviewer nothing about whether to trust them.
write_pr_text() { # resolved.tsv moved blocked
  local resolved="$1" moved="$2" blocked="$3"
  local body="$OUT/pr-body.md"
  local repo cur latest decision mech skipped detail kind

  {
    printf 'rolling: %d tool(s) moved upstream' "$moved"
    [ "$blocked" -gt 0 ] && printf ', %d held back' "$blocked"
    printf '\n'
  } > "$OUT/pr-title.txt"

  {
    echo "Upstream moved. This PR carries the **version diff only** — no layer has been"
    echo "assembled, signed or published, and merging it is what triggers the signed deposit."
    echo
    echo "## What moved"
    echo
    echo "| repo | from | to | move | releases since the pin | vouched by |"
    echo "|---|---|---|---|---|---|"
    while IFS="$TAB" read -r repo cur latest decision mech skipped detail; do
      [ "$decision" = move ] || continue
      kind="$(bump_kind "$cur" "$latest")"
      printf '| `%s` | `%s` | `%s` | %s | %s | `%s` — %s |\n' \
        "$repo" "$cur" "$latest" "$kind" "$skipped" "$mech" "$detail"
    done < "$resolved"
    echo

    if [ "$blocked" -gt 0 ]; then
      echo "## Held at the current pin"
      echo
      echo "A new release that nothing vouches for blocks **that tool**, not this proposal."
      echo "The rest of the layer moves; these keep their existing pins and will be picked up"
      echo "by a later scan if the upstream starts attesting."
      echo
      echo "| repo | pinned at | upstream has | why it is held |"
      echo "|---|---|---|---|"
      while IFS="$TAB" read -r repo cur latest decision mech skipped detail; do
        [ "$decision" = blocked ] || continue
        printf '| `%s` | `%s` | `%s` | %s |\n' "$repo" "$cur" "$latest" "$detail"
      done < "$resolved"
      echo
    fi

    if grep -q "${TAB}hold${TAB}" "$resolved"; then
      echo "## Not resolved"
      echo
      while IFS="$TAB" read -r repo cur latest decision mech skipped detail; do
        [ "$decision" = hold ] || continue
        printf -- '- `%s` (pinned `%s`): %s\n' "$repo" "$cur" "$detail"
      done < "$resolved"
      echo
    fi

    echo "## Unchanged"
    echo
    printf -- '-'
    while IFS="$TAB" read -r repo cur latest decision mech skipped detail; do
      [ "$decision" = current ] || continue
      printf ' `%s@%s`' "$repo" "$cur"
    done < "$resolved"
    echo
    echo

    echo "## Assembly gate"
    echo
    case "$GATE" in
      pass) echo "\`tools/systest/deposit-layer.sh\` ran against **these** pins and passed${GATE_URL:+ ([run]($GATE_URL))} — the proposal is known-assemblable." ;;
      fail) echo "> [!WARNING]" ;
            echo "> \`tools/systest/deposit-layer.sh\` FAILED against these pins${GATE_URL:+ ([run]($GATE_URL))}. Do not merge: the deposit would fail the same way." ;;
      *)    echo "The assembly gate was not run for this proposal (\`--gate\` was \`$GATE\`). Do not merge until it has." ;;
    esac
    echo
    echo "## Why this is a PR and not a published layer"
    echo
    echo "In varve, \`channel = \"rolling\"\` is an annotation inside a layer signed by the same"
    echo "realm root as \`qualified\` — the realm is the trust boundary, not the channel. Publishing"
    echo "on a timer would mean the realm root signing unattended, dozens of times a week, against"
    echo "everything \`varve docs root-ceremony\` says about that key. varve has no revocation and no"
    echo "rotation, so a layer published in error cannot be withdrawn. The scan automates the toil;"
    echo "the merge is the judgement."
    echo
    echo "---"
    echo "Opened by \`tools/scan-upstream.sh\` (REQ-ROLLING-001). Re-run the scan to refresh."
  } > "$body"
}

# ── propose: branch + PR, and ONLY with --apply ──────────────────────────────
propose() {
  local status; status="$(cat "$OUT/status" 2>/dev/null || echo missing)"
  if [ "$status" != moved ]; then
    echo "== status is '$status' — nothing to propose"
    return 0
  fi
  [ -f "$OUT/deposit-layer.yml.proposed" ] || die "no proposal in $OUT — run 'scan' first"
  # The body is regenerated here so the gate verdict this invocation was given
  # lands in the PR text rather than in a log nobody opens.
  write_pr_text "$OUT/resolved.tsv" \
    "$(grep -c "${TAB}move${TAB}" "$OUT/resolved.tsv" || true)" \
    "$(grep -c "${TAB}blocked${TAB}" "$OUT/resolved.tsv" || true)"

  local title; title="$(cat "$OUT/pr-title.txt")"

  if [ "$APPLY" != 1 ]; then
    # The default. Everything below is shown, nothing is run — a dry run that
    # could open a PR by forgetting a flag is not a dry run.
    echo "== DRY RUN (no --apply / VARVE_SCAN_APPLY=1): would open or update a PR"
    echo "   branch: $BRANCH -> $BASE"
    echo "   title:  $title"
    echo "   file:   .github/workflows/deposit-layer.yml"
    echo "── diff ─────────────────────────────────────────────────────────────"
    cat "$OUT/pins.diff"
    echo "── body ─────────────────────────────────────────────────────────────"
    cat "$OUT/pr-body.md"
    return 0
  fi

  echo "== opening/updating $BRANCH"
  git -C "$REPO_ROOT" config user.name  "${GIT_AUTHOR_NAME:-github-actions[bot]}"
  git -C "$REPO_ROOT" config user.email "${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
  git -C "$REPO_ROOT" checkout -B "$BRANCH"
  cp "$OUT/deposit-layer.yml.proposed" "$REPO_ROOT/.github/workflows/deposit-layer.yml"
  git -C "$REPO_ROOT" add .github/workflows/deposit-layer.yml
  git -C "$REPO_ROOT" commit -F - <<COMMITEOF
$title

$(awk -F"$TAB" '$4=="move"  {printf "  %s %s -> %s (vouched by %s)\n", $1, $2, $3, $5}
                $4=="blocked"{printf "  %s held at %s (%s has %s, unvouched)\n", $1, $2, $1, $3}' \
      "$OUT/resolved.tsv")

Proposed by tools/scan-upstream.sh (REQ-ROLLING-001). No layer has been
assembled, signed or published; merging this is what triggers the deposit.
COMMITEOF
  # One standing proposal branch, force-pushed: the PR always shows the CURRENT
  # upstream state rather than accumulating one stale PR per scan.
  git -C "$REPO_ROOT" push --force origin "HEAD:refs/heads/$BRANCH"

  local existing
  existing="$(gh pr list --head "$BRANCH" --base "$BASE" --state open --json number --jq '.[0].number' 2>/dev/null || true)"
  if [ -n "$existing" ]; then
    gh pr edit "$existing" --title "$title" --body-file "$OUT/pr-body.md"
    echo "== updated PR #$existing"
  else
    gh pr create --base "$BASE" --head "$BRANCH" --title "$title" --body-file "$OUT/pr-body.md"
  fi
}

# ── pins: the layer's contents, normalised ───────────────────────────────────
# One line per repo, sorted. Used by the merge trigger to answer "did the pins
# actually change in this push?" — a comment edit or a whitespace change in
# deposit-layer.yml must not dispatch a signed deposit, and diffing the FILE
# cannot tell those apart from a bump.
pins_of() {
  [ -f "$WORKFLOW" ] || die "no such workflow: $WORKFLOW"
  local tarball wsc vsix entry tool rest version
  tarball="$(wf_env TARBALL_TOOLS)"; wsc="$(wf_env WSC_VERSION)"; vsix="$(wf_env VSIX_PACKAGES)"
  { [ -n "$tarball" ] && [ -n "$wsc" ] && [ -n "$vsix" ]; } \
    || die "could not read the pin set out of $WORKFLOW"
  {
    for entry in $tarball $vsix; do
      tool="${entry%%:*}"; rest="${entry#*:}"; version="${rest%%:*}"
      printf '%s\t%s\n' "$(entry_repo "$tool")" "$version"
    done
    printf '%s\t%s\n' pulseengine/sigil "$wsc"
  } | sort -u
}

case "$CMD" in
  scan)    scan ;;
  propose) propose ;;
  pins)    pins_of ;;
  *) echo "usage: $0 {scan|propose|pins} --out DIR [...]" >&2; exit 2 ;;
esac
