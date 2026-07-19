#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARM_BUILD="$ROOT_DIR/.build/hook-release-arm64"
X86_BUILD="$ROOT_DIR/.build/hook-release-x86_64"
OUTPUT_DIR="$ROOT_DIR/bin"
OUTPUT="$OUTPUT_DIR/CerebroAgentReceiptHook"

mkdir -p "$ARM_BUILD" "$X86_BUILD" "$OUTPUT_DIR"

swift build \
  --package-path "$ROOT_DIR" \
  --configuration release \
  --arch arm64 \
  --scratch-path "$ARM_BUILD" \
  --product CerebroAgentReceiptHook

swift build \
  --package-path "$ROOT_DIR" \
  --configuration release \
  --arch x86_64 \
  --scratch-path "$X86_BUILD" \
  --product CerebroAgentReceiptHook

lipo -create \
  "$ARM_BUILD/release/CerebroAgentReceiptHook" \
  "$X86_BUILD/release/CerebroAgentReceiptHook" \
  -output "$OUTPUT"
chmod 0755 "$OUTPUT"
codesign --force --sign - --timestamp=none "$OUTPUT"
codesign --verify --strict --verbose=2 "$OUTPUT"
file "$OUTPUT"
