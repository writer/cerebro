#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DATA_DIR="${PLUGIN_DATA:-${TMPDIR:-/tmp}/cerebro-agent-receipts-plugin}"
SCRATCH_DIR="$DATA_DIR/swift-build"
BIN_DIR="$DATA_DIR/bin"
APP_BINARY="$BIN_DIR/CerebroAgentReceiptHook"
BUNDLED_BINARY="$ROOT_DIR/bin/CerebroAgentReceiptHook"
INSTALLED_BINARY="${CEREBRO_AGENT_RECEIPTS_INSTALLED_HELPER:-$HOME/Library/Application Support/com.writer.cerebro.agent-receipts/bin/CerebroAgentReceiptHook}"

if [[ "${CEREBRO_AGENT_RECEIPTS_BUILD_FROM_SOURCE:-0}" != "1" ]] && [[ -x "$INSTALLED_BINARY" ]]; then
  codesign --verify --strict "$INSTALLED_BINARY"
  exec "$INSTALLED_BINARY" "$@"
fi

if [[ "${CEREBRO_AGENT_RECEIPTS_BUILD_FROM_SOURCE:-0}" != "1" ]] && [[ -x "$BUNDLED_BINARY" ]]; then
  codesign --verify --strict "$BUNDLED_BINARY"
  exec "$BUNDLED_BINARY" "$@"
fi

mkdir -p "$BIN_DIR" "$SCRATCH_DIR"

if [[ ! -x "$APP_BINARY" ]] || [[ "${CEREBRO_AGENT_RECEIPTS_BUILD_FROM_SOURCE:-0}" == "1" ]]; then
  swift build \
    --package-path "$ROOT_DIR" \
    --scratch-path "$SCRATCH_DIR" \
    --product CerebroAgentReceiptHook >&2
  cp "$SCRATCH_DIR/debug/CerebroAgentReceiptHook" "$APP_BINARY"
  chmod +x "$APP_BINARY"
fi

codesign --verify --strict "$APP_BINARY"
exec "$APP_BINARY" "$@"
