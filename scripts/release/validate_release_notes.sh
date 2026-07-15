#!/usr/bin/env bash
set -euo pipefail

notes="${1:-}"
if [ -z "${notes}" ] || [ ! -f "${notes}" ]; then
  echo "usage: $0 RELEASE_NOTES.md" >&2
  exit 2
fi

required_sections=(
  "Compatibility"
  "Migrations"
  "Configuration"
  "Content packs"
  "Rollback"
  "Runtime contract"
  "Smoke evidence"
  "Supported versions"
)

failed=0
for section in "${required_sections[@]}"; do
  if ! grep -Eiq "^##[[:space:]]+${section}[[:space:]]*$" "${notes}"; then
    echo "ERROR: release notes missing '## ${section}'" >&2
    failed=1
  fi
done

if grep -Eq '\{\{[^}]+\}\}|\bTBD\b|\bTODO\b|\bREPLACE_ME\b' "${notes}"; then
  echo "ERROR: release notes contain an unfinished placeholder" >&2
  failed=1
fi

if [ "$(wc -w < "${notes}")" -lt 40 ]; then
  echo "ERROR: release notes must record concrete compatibility and recovery decisions" >&2
  failed=1
fi

exit "${failed}"
