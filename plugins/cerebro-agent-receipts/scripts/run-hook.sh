#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DATA_DIR="${PLUGIN_DATA:-${TMPDIR:-/tmp}/cerebro-agent-receipts-plugin}"
SCRATCH_DIR="$DATA_DIR/swift-build"
BIN_DIR="$DATA_DIR/bin"
APP_BINARY="$BIN_DIR/CerebroAgentReceiptHook"

mkdir -p "$BIN_DIR" "$SCRATCH_DIR"

if [[ ! -x "$APP_BINARY" ]] || find "$ROOT_DIR/Package.swift" "$ROOT_DIR/Sources/ReceiptCore" "$ROOT_DIR/Sources/CerebroAgentReceiptHook" -newer "$APP_BINARY" -print -quit | grep -q .; then
  swift build \
    --package-path "$ROOT_DIR" \
    --scratch-path "$SCRATCH_DIR" \
    --product CerebroAgentReceiptHook >&2
  cp "$SCRATCH_DIR/debug/CerebroAgentReceiptHook" "$APP_BINARY"
  chmod +x "$APP_BINARY"
fi

exec "$APP_BINARY" "$@"
