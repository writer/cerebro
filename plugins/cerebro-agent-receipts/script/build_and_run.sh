#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="CerebroAgentReceipts"
BUNDLE_ID="com.writer.cerebro.agent-receipts"
MIN_SYSTEM_VERSION="14.0"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_HELPERS="$APP_CONTENTS/Helpers"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_LAUNCH_AGENTS="$APP_CONTENTS/Library/LaunchAgents"
APP_BINARY="$APP_MACOS/$APP_NAME"
HOOK_HELPER="$APP_HELPERS/CerebroAgentReceiptHook"
SHIELD_AGENT="$APP_RESOURCES/CerebroShieldAgent"
SHIELD_AGENT_LABEL="com.writer.cerebro.agent-receipts.shield-agent.v3"
SHIELD_AGENT_PLIST="$APP_LAUNCH_AGENTS/$SHIELD_AGENT_LABEL.plist"
INFO_PLIST="$APP_CONTENTS/Info.plist"

if [[ -x "$APP_BINARY" ]]; then
  "$APP_BINARY" --unregister-agent-and-quit >/dev/null 2>&1 &
  UPDATE_PID=$!
  for _ in {1..100}; do
    kill -0 "$UPDATE_PID" >/dev/null 2>&1 || break
    sleep 0.1
  done
  if kill -0 "$UPDATE_PID" >/dev/null 2>&1; then
    echo "timed out while unregistering the existing shield agent" >&2
    kill "$UPDATE_PID" >/dev/null 2>&1 || true
    wait "$UPDATE_PID" 2>/dev/null || true
    exit 1
  fi
  # A partial development bundle may not have a registered login item yet.
  wait "$UPDATE_PID" || true
fi
pkill -x "$APP_NAME" >/dev/null 2>&1 || true

"$ROOT_DIR/script/build_hook_release.sh"
swift build --package-path "$ROOT_DIR" --product "$APP_NAME"
BUILD_BINARY="$(swift build --package-path "$ROOT_DIR" --show-bin-path)/$APP_NAME"
swift build --package-path "$ROOT_DIR" --product CerebroShieldAgent
SHIELD_AGENT_BINARY="$(swift build --package-path "$ROOT_DIR" --show-bin-path)/CerebroShieldAgent"

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_MACOS" "$APP_HELPERS" "$APP_RESOURCES" "$APP_LAUNCH_AGENTS"
cp "$BUILD_BINARY" "$APP_BINARY"
cp "$ROOT_DIR/bin/CerebroAgentReceiptHook" "$HOOK_HELPER"
cp "$SHIELD_AGENT_BINARY" "$SHIELD_AGENT"
chmod +x "$APP_BINARY"
chmod +x "$HOOK_HELPER"
chmod +x "$SHIELD_AGENT"

cat >"$SHIELD_AGENT_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$SHIELD_AGENT_LABEL</string>
  <key>BundleProgram</key>
  <string>Contents/Resources/CerebroShieldAgent</string>
  <key>MachServices</key>
  <dict>
    <key>com.writer.cerebro.agent-receipts.shield-agent</key>
    <true/>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>CEREBRO_SHIELD_DEVELOPMENT_KEY_FILE</key>
    <string>1</string>
  </dict>
</dict>
</plist>
PLIST

cat >"$INFO_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$APP_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleName</key>
  <string>Cerebro Shield</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSMinimumSystemVersion</key>
  <string>$MIN_SYSTEM_VERSION</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

/usr/bin/codesign --force --sign - --identifier "$SHIELD_AGENT_LABEL" \
  --requirements "=designated => identifier \"$SHIELD_AGENT_LABEL\"" "$SHIELD_AGENT"
/usr/bin/codesign --force --sign - --identifier "$BUNDLE_ID" "$APP_BUNDLE"

open_app() {
  /usr/bin/open -n "$APP_BUNDLE" --args --show-status
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --telemetry|telemetry)
    open_app
    /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    /usr/bin/open -n "$APP_BUNDLE"
    sleep 1
    pgrep -x "$APP_NAME" >/dev/null
    /usr/bin/codesign --verify --deep --strict "$APP_BUNDLE"
    launchctl print "gui/$(id -u)/$SHIELD_AGENT_LABEL" \
      | grep -q 'state = running'
    "$HOOK_HELPER" ping
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
