#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Wrap the nix-built sinete CLI in a minimal signed .app bundle so macOS will
# launch it with Secure Enclave entitlements.
#
# Why: SE key ops need the `com.apple.application-identifier` entitlement, which
# is RESTRICTED — macOS (AMFI) SIGKILLs a binary that claims it unless an embedded
# provisioning profile authorizes it. A bare Mach-O CLI can't carry a profile;
# only a bundle can (Contents/embedded.provisionprofile). So we bundle.
#
# Usage:   scripts/bundle-and-sign.sh /path/to/sinete.provisionprofile [sinete args...]
# Identity override: SINETE_SIGN_IDENTITY="Apple Development: ... (USERID)"
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profile="${1:?usage: bundle-and-sign.sh <path-to.provisionprofile> [args...]}"
shift || true
identity="${SINETE_SIGN_IDENTITY:-Apple Development: Paulo Duarte (P6K8K4X996)}"
bin="$repo/result/bin/sinete"
ent="$repo/sinete.entitlements"
app="$repo/sinete.app"
iconfile="$repo/assets/AppIcon.icon"
bundle_id="me.paulofduarte.sinete"

[ -x "$bin" ] || {
  echo "no build output at $bin — run 'nix build' first" >&2
  exit 1
}
[ -f "$profile" ] || {
  echo "provisioning profile not found: $profile" >&2
  exit 1
}

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp -f "$bin" "$app/Contents/MacOS/sinete"
chmod u+w "$app/Contents/MacOS/sinete"
cp -f "$profile" "$app/Contents/embedded.provisionprofile"

# App icon (Liquid Glass: light/dark/tinted). actool (Xcode 26+) compiles the
# Icon Composer .icon into a layered Assets.car plus a backward-compatible
# AppIcon.icns. Skipped (no icon) if actool is unavailable.
icon_keys=""
if [ -d "$iconfile" ] && actool="$(xcrun --find actool 2>/dev/null)"; then
  mkdir -p "$app/Contents/Resources"
  "$actool" "$iconfile" --compile "$app/Contents/Resources" --app-icon AppIcon \
    --output-partial-info-plist "$(mktemp)" \
    --platform macosx --minimum-deployment-target 26.0 >/dev/null 2>&1 || true
  if [ -f "$app/Contents/Resources/Assets.car" ]; then
    icon_keys=$'    <key>CFBundleIconFile</key><string>AppIcon</string>\n    <key>CFBundleIconName</key><string>AppIcon</string>'
    echo "embedded app icon (light/dark/tinted)"
  fi
fi

cat >"$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>sinete</string>
    <key>CFBundleIdentifier</key><string>${bundle_id}</string>
    <key>CFBundleName</key><string>sinete</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.0.0-dev</string>
    <key>LSBackgroundOnly</key><true/>
${icon_keys}
</dict>
</plist>
PLIST

# No hardened runtime for the local dev test: the nix-store dylibs are ad-hoc
# signed, and hardened runtime's library validation rejects non-team-signed libs
# (a distributable build would instead add com.apple.security.cs.disable-library-validation).
codesign --force --sign "$identity" --entitlements "$ent" "$app"
echo "--- signature / profile ---"
codesign -dvvv "$app" 2>&1 | grep -iE "TeamIdentifier|provision" || true

echo "--- running (expect a Touch ID prompt) ---"
exec "$app/Contents/MacOS/sinete" "$@"
