#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_mod="${root_dir}/go.mod"

if [ ! -f "${go_mod}" ]; then
  echo "go.mod not found at ${go_mod}" >&2
  exit 1
fi

version="$(awk '/^go [0-9]/{print $2; exit}' "${go_mod}")"

if [ -z "${version}" ]; then
  echo "unable to determine Go version from ${go_mod}" >&2
  exit 1
fi

printf '%s\n' "${version}"
