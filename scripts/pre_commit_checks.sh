#!/usr/bin/env bash
set -euo pipefail

export PATH="${GOPATH:-$HOME/go}/bin:$PATH"

staged_go="$(git diff --cached --name-only --diff-filter=ACM -- '*.go' | grep -v '^vendor/' || true)"
if [ -n "$staged_go" ]; then
  unformatted="$(printf '%s\n' "$staged_go" | xargs gofmt -l 2>/dev/null || true)"
  if [ -n "$unformatted" ]; then
    echo "gofmt: fixing staged Go files..."
    printf '%s\n' "$unformatted" | xargs gofmt -w
    printf '%s\n' "$unformatted" | xargs git add
  fi
fi

make verify
