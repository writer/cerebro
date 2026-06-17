#!/usr/bin/env bash
set -euo pipefail

export PATH="${GOPATH:-$HOME/go}/bin:$PATH"

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

if [ "${CEREBRO_SKIP_LEAK_CHECK:-}" != "1" ]; then
  "$repo_root/scripts/leak_check.sh" staged
fi

staged_go="$(git diff --cached --name-only --diff-filter=ACM -- '*.go' | grep -v '^vendor/' || true)"
if [ -n "$staged_go" ]; then
  unformatted="$(printf '%s\n' "$staged_go" | xargs gofmt -l 2>/dev/null || true)"
  if [ -n "$unformatted" ]; then
    echo "gofmt: fixing staged Go files..."
    printf '%s\n' "$unformatted" | xargs gofmt -w
    printf '%s\n' "$unformatted" | xargs git add
  fi
fi

if [ "${CEREBRO_PRE_COMMIT_FULL_VERIFY:-}" = "1" ]; then
  echo "verify: running full local validation, including golangci-lint..."
  make verify
else
  echo "changed-check: running validation selected from changed paths..."
  make changed-check
fi
