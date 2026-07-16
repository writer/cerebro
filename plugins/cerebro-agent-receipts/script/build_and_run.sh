#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="CerebroAgentReceipts"
BUNDLE_ID="com.writer.cerebro.agent-receipts"
MIN_SYSTEM_VERSION="14.0"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
FINAL_APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
FINAL_APP_BINARY="$FINAL_APP_BUNDLE/Contents/MacOS/$APP_NAME"
FINAL_HOOK_HELPER="$FINAL_APP_BUNDLE/Contents/Helpers/CerebroAgentReceiptHook"
APP_BUNDLE="$DIST_DIR/.$APP_NAME.staging.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_HELPERS="$APP_CONTENTS/Helpers"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_LAUNCH_AGENTS="$APP_CONTENTS/Library/LaunchAgents"
APP_BINARY="$APP_MACOS/$APP_NAME"
HOOK_HELPER="$APP_HELPERS/CerebroAgentReceiptHook"
SHIELD_AGENT="$APP_RESOURCES/CerebroShieldAgent"
SHIELD_AGENT_LABEL="com.writer.cerebro.agent-receipts.shield-agent.v5"
SHIELD_AGENT_PLIST="$APP_LAUNCH_AGENTS/$SHIELD_AGENT_LABEL.plist"
INFO_PLIST="$APP_CONTENTS/Info.plist"

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
/usr/bin/codesign --verify --deep --strict "$APP_BUNDLE"

OLD_AGENT_LABELS=()
if [[ -d "$FINAL_APP_BUNDLE/Contents/Library/LaunchAgents" ]]; then
  while IFS= read -r plist; do
    label="$(/usr/libexec/PlistBuddy -c 'Print :Label' "$plist")"
    [[ -n "$label" ]] && OLD_AGENT_LABELS+=("$label")
  done < <(find "$FINAL_APP_BUNDLE/Contents/Library/LaunchAgents" -type f -name '*.plist')
fi
if [[ -x "$FINAL_APP_BINARY" ]]; then
  "$FINAL_APP_BINARY" --unregister-agent-and-quit
fi
for label in "${OLD_AGENT_LABELS[@]}"; do
  for _ in {1..100}; do
    if ! launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1; then break; fi
    sleep 0.1
  done
  if launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1; then
    echo "the previous shield agent is still registered: $label" >&2
    exit 1
  fi
done
if [[ -x "$FINAL_HOOK_HELPER" ]] && "$FINAL_HOOK_HELPER" ping >/dev/null 2>&1; then
  echo "the previous shield endpoint is still reachable" >&2
  exit 1
fi
rm -rf "$FINAL_APP_BUNDLE"
mv "$APP_BUNDLE" "$FINAL_APP_BUNDLE"

open_app() {
  /usr/bin/open -n "$FINAL_APP_BUNDLE" --args --show-status
}

wait_for_agent() {
  for _ in {1..100}; do
    if launchctl print "gui/$(id -u)/$SHIELD_AGENT_LABEL" 2>/dev/null \
      | grep -q 'state = running' && "$FINAL_HOOK_HELPER" ping >/dev/null 2>&1
    then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    lldb -- "$FINAL_APP_BINARY"
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
    /usr/bin/open -n "$FINAL_APP_BUNDLE"
    /usr/bin/codesign --verify --deep --strict "$FINAL_APP_BUNDLE"
    if ! wait_for_agent; then
      # ServiceManagement can retain the replaced bundle's lightweight code
      # requirement briefly even after the old job disappears. Re-register the
      # exact final bundle once so launchd refreshes that requirement.
      pkill -x "$APP_NAME" >/dev/null 2>&1 || true
      /usr/bin/open -n "$FINAL_APP_BUNDLE" --args --reregister-agent --show-status
      wait_for_agent
    fi
    pgrep -x "$APP_NAME" >/dev/null
    launchctl print "gui/$(id -u)/$SHIELD_AGENT_LABEL" | grep -q 'state = running'
    "$FINAL_HOOK_HELPER" ping
    "$FINAL_HOOK_HELPER" delivery-health
    STABLE_PID="$(launchctl print "gui/$(id -u)/$SHIELD_AGENT_LABEL" | awk '/pid =/{print $3; exit}')"
    sleep 12
    launchctl print "gui/$(id -u)/$SHIELD_AGENT_LABEL" | grep -q 'state = running'
    CURRENT_PID="$(launchctl print "gui/$(id -u)/$SHIELD_AGENT_LABEL" | awk '/pid =/{print $3; exit}')"
    [[ -n "$STABLE_PID" && "$CURRENT_PID" == "$STABLE_PID" ]]
    "$FINAL_HOOK_HELPER" ping
    "$FINAL_HOOK_HELPER" delivery-health >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
