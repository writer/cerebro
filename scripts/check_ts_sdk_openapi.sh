#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required to export the OpenAPI schema. Install uv or ensure it is on your PATH." >&2
  exit 1
fi

uv run python scripts/export_openapi.py --output sdk/ts/tmp/openapi.json

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to regenerate TypeScript types." >&2
  exit 1
fi

CEREBRO_OPENAPI_SPEC_PATH="sdk/ts/tmp/openapi.json" npm run generate:types --prefix sdk/ts >/dev/null

if ! git diff --quiet -- sdk/ts/src/generated/openapi.ts; then
  echo "The generated OpenAPI types have changed. Stage sdk/ts/src/generated/openapi.ts after reviewing the updates." >&2
  exit 1
fi

exit 0
