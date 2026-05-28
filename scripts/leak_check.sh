#!/usr/bin/env bash
# Scans staged content, commit messages, and refs being pushed for
# tenant-specific identifiers that must not land in the public cerebro
# repository (e.g. internal runtime IDs, environment hostnames,
# credential formats).
#
# Modes (first positional argument):
#   staged                 scan staged diff content (pre-commit)
#   commit-msg <path>      scan a commit message file (commit-msg)
#   pushed                 read pre-push stdin and scan commits being pushed
#   range <base..head>     scan a git revision range (used by CI; range may
#                          be passed as a single positional argument or via
#                          $LEAK_CHECK_BASE_REF and $LEAK_CHECK_HEAD_REF)
#   pr-body <title> <body> scan a PR title and body (also reads PR_TITLE /
#                          PR_BODY from the environment when args are empty)
#
# Bypass: set CEREBRO_LEAK_CHECK_BYPASS=1 to skip the check. Bypasses are
# logged so they show up in shell history and CI logs.
#
# Additional patterns may be supplied via a user-local file at
# $CEREBRO_LEAK_USER_PATTERNS (default: $HOME/.config/cerebro/leak_patterns.txt).
# That file is intended for entries that should NOT be tracked in the repo
# (e.g. specific human handles).

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
patterns_file="${repo_root}/scripts/leak_patterns.txt"
user_patterns_file="${CEREBRO_LEAK_USER_PATTERNS:-$HOME/.config/cerebro/leak_patterns.txt}"

if [ "${CEREBRO_LEAK_CHECK_BYPASS:-}" = "1" ]; then
  echo "leak-check: BYPASS via CEREBRO_LEAK_CHECK_BYPASS=1 (mode=${1:-?})" >&2
  exit 0
fi

if [ ! -f "$patterns_file" ]; then
  echo "leak-check: patterns file missing at $patterns_file" >&2
  exit 1
fi

mode="${1:-staged}"
shift || true

collect_patterns() {
  grep -vE '^[[:space:]]*(#|$)' "$patterns_file"
  if [ -f "$user_patterns_file" ]; then
    grep -vE '^[[:space:]]*(#|$)' "$user_patterns_file" || true
  fi
}

patterns="$(collect_patterns || true)"

if [ -z "$patterns" ]; then
  echo "leak-check: no patterns configured (mode=$mode)" >&2
  exit 0
fi

# redact_matches <input> <pattern>
# Replaces each occurrence of <pattern> in <input> with a length-only
# placeholder so the hook never echoes the offending substring back to
# stderr (which would land in shell history / CI logs).
#
# Uses perl for portable, ERE-equivalent regex with \b support and
# falls back to a coarse line-level scrub if perl is unavailable.
redact_matches() {
  local input="$1"
  local pattern="$2"
  if command -v perl >/dev/null 2>&1; then
    PATTERN="$pattern" perl -ne '
      BEGIN { $p = $ENV{PATTERN} }
      s/$p/"<REDACTED:len=" . length($&) . ">"/ge;
      print;
    ' <<<"$input"
  else
    printf '%s\n' "$input" | sed -E "s/$pattern/<REDACTED>/g"
  fi
}

# scan_input <label> <input>
# Returns 0 if clean, 1 if any pattern matched. Matches are printed to
# stderr with the offending substring replaced by <REDACTED:len=N>.
scan_input() {
  local label="$1"
  local input="$2"
  local matched=0
  while IFS= read -r pattern; do
    [ -z "$pattern" ] && continue
    local hits
    hits="$(printf '%s\n' "$input" | grep -E -n -- "$pattern" || true)"
    if [ -n "$hits" ]; then
      matched=1
      printf '%s: pattern matched (%d hit(s))\n' "$label" "$(printf '%s\n' "$hits" | wc -l | tr -d ' ')" >&2
      local redacted
      redacted="$(redact_matches "$hits" "$pattern")"
      printf '%s\n' "$redacted" | sed 's/^/  /' >&2
    fi
  done <<<"$patterns"
  [ "$matched" -eq 0 ]
}

ignored_path_re='^(vendor/|scripts/leak_patterns\.txt$|go\.sum$|.*\.pem$|.*\.crt$)'

case "$mode" in
  staged)
    staged_files="$(git diff --cached --name-only --diff-filter=ACM | grep -vE "$ignored_path_re" || true)"
    if [ -z "$staged_files" ]; then
      exit 0
    fi
    diff_content="$(git diff --cached --no-color -- $staged_files | grep '^+' | grep -v '^+++' || true)"
    if [ -z "$diff_content" ]; then
      exit 0
    fi
    if ! scan_input "<staged>" "$diff_content"; then
      cat >&2 <<'EOF'

leak-check: tenant data pattern matched in staged changes.

  - Review the matches above.
  - If the match is a false positive, narrow the pattern in
    scripts/leak_patterns.txt or use synthetic data.
  - If the match is intentional (e.g. fixture-only), you can bypass
    with: CEREBRO_LEAK_CHECK_BYPASS=1 git commit ...
    Bypasses are logged.
EOF
      exit 1
    fi
    ;;

  commit-msg)
    msg_file="${1:?commit-msg mode requires a path to the commit message file}"
    if [ ! -f "$msg_file" ]; then
      echo "leak-check: commit message file not found: $msg_file" >&2
      exit 1
    fi
    msg="$(cat "$msg_file")"
    if ! scan_input "<commit-msg>" "$msg"; then
      echo "" >&2
      echo "leak-check: tenant data pattern matched in commit message." >&2
      echo "leak-check: rewrite the message or bypass with CEREBRO_LEAK_CHECK_BYPASS=1" >&2
      exit 1
    fi
    ;;

  range)
    if [ "$#" -ge 1 ] && [ -n "${1:-}" ]; then
      range="$1"
    else
      base_ref="${LEAK_CHECK_BASE_REF:-origin/main}"
      head_ref="${LEAK_CHECK_HEAD_REF:-HEAD}"
      range="${base_ref}...${head_ref}"
    fi
    base_part="${range%%.*}"
    head_part="${range##*.}"
    if [ -z "$base_part" ] || ! git rev-parse --verify "$base_part" >/dev/null 2>&1; then
      echo "leak-check: cannot resolve base ref for range '$range'" >&2
      exit 1
    fi
    if [ -z "$head_part" ] || ! git rev-parse --verify "$head_part" >/dev/null 2>&1; then
      echo "leak-check: cannot resolve head ref for range '$range'" >&2
      exit 1
    fi
    commits_meta="$(git log --format='%H%n%s%n%b%n%an %ae%n---' "$range" 2>/dev/null || true)"
    commits_diff="$(git diff --no-color "$range" 2>/dev/null | grep '^+' | grep -v '^+++' || true)"
    combined="${commits_meta}
${commits_diff}"
    if [ -z "$(printf '%s' "$commits_meta$commits_diff" | tr -d '[:space:]')" ]; then
      echo "leak-check: range '$range' has no commits/diff to scan" >&2
      exit 0
    fi
    if ! scan_input "<range:$range>" "$combined"; then
      echo "" >&2
      echo "leak-check: tenant data pattern matched in range $range" >&2
      echo "leak-check: amend or drop the offending commits, or set CEREBRO_LEAK_CHECK_BYPASS=1 (logged)" >&2
      exit 1
    fi
    ;;

  pushed)
    # git invokes pre-push with: <remote> <url>; refs come on stdin as
    # <local-ref> <local-sha> <remote-ref> <remote-sha>.
    zero="0000000000000000000000000000000000000000"
    saw_any=0
    while read -r local_ref local_sha remote_ref remote_sha; do
      saw_any=1
      if [ "$local_sha" = "$zero" ]; then
        continue
      fi
      if [ "$remote_sha" = "$zero" ]; then
        base=""
        if git rev-parse --verify origin/HEAD >/dev/null 2>&1; then
          base="$(git merge-base origin/HEAD "$local_sha" 2>/dev/null || true)"
        fi
        if [ -n "$base" ]; then
          range="${base}..${local_sha}"
        else
          range="$local_sha"
        fi
      else
        range="${remote_sha}..${local_sha}"
      fi
      commits_meta="$(git log --format='%H%n%s%n%b%n%an %ae%n---' "$range" 2>/dev/null || true)"
      commits_diff="$(git diff --no-color "$range" 2>/dev/null | grep '^+' | grep -v '^+++' || true)"
      combined="${commits_meta}
${commits_diff}"
      if ! scan_input "<pushed:$local_ref>" "$combined"; then
        echo "" >&2
        echo "leak-check: tenant data pattern matched in commits pushed to $remote_ref" >&2
        echo "leak-check: amend or drop the offending commits, or bypass with CEREBRO_LEAK_CHECK_BYPASS=1" >&2
        exit 1
      fi
    done
    if [ "$saw_any" = "0" ]; then
      exit 0
    fi
    ;;

  pr-body)
    # Scans a PR title and body supplied via environment variables or
    # positional arguments: pr-body <title> <body>
    # Can also read PR_TITLE / PR_BODY from the environment.
    pr_title="${1:-${PR_TITLE:-}}"
    pr_body="${2:-${PR_BODY:-}}"
    shift 2 2>/dev/null || true
    pr_content="${pr_title}
${pr_body}"
    if [ -z "$(printf '%s' "$pr_content" | tr -d '[:space:]')" ]; then
      exit 0
    fi
    if ! scan_input "<pr-body>" "$pr_content"; then
      cat >&2 <<'EOF'

leak-check: tenant data pattern matched in PR title or body.

  - Review the matches above.
  - Rewrite the PR description to remove tenant-specific data.
  - See AGENTS.md "Public PR Data Safety" for guidance.
EOF
      exit 1
    fi
    ;;

  *)
    echo "leak-check: unknown mode '$mode' (expected: staged | commit-msg | pushed | range | pr-body)" >&2
    exit 1
    ;;
esac

exit 0
