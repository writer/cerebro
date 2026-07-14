#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
validator="${root}/scripts/release/validate_release_notes.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

cp "${root}/scripts/release/testdata/release-notes-valid.md" "${tmp}/valid.md"
"${validator}" "${tmp}/valid.md"

sed '/^## Rollback$/d' "${tmp}/valid.md" > "${tmp}/missing.md"
if "${validator}" "${tmp}/missing.md" 2> "${tmp}/error"; then
  echo "ERROR: validator accepted notes without a rollback section" >&2
  exit 1
fi
grep -Fq "missing '## Rollback'" "${tmp}/error"

sed 's/No configuration keys changed./TBD/' "${tmp}/valid.md" > "${tmp}/placeholder.md"
if "${validator}" "${tmp}/placeholder.md" 2> "${tmp}/error"; then
  echo "ERROR: validator accepted an unfinished placeholder" >&2
  exit 1
fi
grep -Fq "unfinished placeholder" "${tmp}/error"

echo "release notes validator tests passed"
