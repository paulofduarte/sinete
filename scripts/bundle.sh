#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Build and codesign dist/sinete.app so the Secure Enclave is reachable (an unsigned/unentitled
# binary is rejected by the SE with -34018 or SIGKILLed by AMFI). `zig build` produces the bare
# binary; this packaging + signing step is intentionally separate (codesign is a macOS platform
# tool, like the linker, and the identity is developer-specific, not a build input).
#
# The Apple identity is parameterized so a fork can sign with its own team without editing tracked
# files; the defaults are this project's. The entitlements are generated from these, not committed.
#
# Usage:  scripts/bundle.sh <path-to.provisionprofile>
# Env:    SINETE_TEAM           Apple Team ID            (default: LDT534J26W)
#         SINETE_BUNDLE_ID      app bundle identifier    (default: me.paulofduarte.sinete)
#         SINETE_SIGN_IDENTITY  codesign identity        (default: "Apple Development: Paulo Duarte")
#
# Must run on the Mac with the login keychain unlocked (not over ssh -> errSecInternalComponent).

set -euo pipefail

profile="${1:-}"
if [ -z "$profile" ] || [ ! -f "$profile" ]; then
    echo "usage: scripts/bundle.sh <path-to.provisionprofile>" >&2
    exit 1
fi

team="${SINETE_TEAM:-LDT534J26W}"
bundle_id="${SINETE_BUNDLE_ID:-me.paulofduarte.sinete}"
identity="${SINETE_SIGN_IDENTITY:-Apple Development: Paulo Duarte}"
access_group="$team.$bundle_id" # the keychain access group SE keys are bound to
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

app="dist/sinete.app"
contents="$app/Contents"

# Build the release binary. Always pass the SDK framework path: it is auto-detected on normal macOS
# environments (a harmless duplicate) and is required inside a bare `nix-shell -p zig`.
fw="$(xcrun --show-sdk-path)/System/Library/Frameworks"
zig build -Doptimize=ReleaseFast -Dframework-path="$fw"

# Assemble the bundle tree. (The login-item launchd plist lands with the SMAppService work; Z3 runs
# the agent directly, so the bundle needs only the binary, profile, and Info.plist.)
rm -rf "$app"
mkdir -p "$contents/MacOS"
cp zig-out/bin/sinete "$contents/MacOS/sinete"
chmod u+w "$contents/MacOS/sinete"
cp "$profile" "$contents/embedded.provisionprofile"

cat >"$contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>sinete</string>
    <key>CFBundleIdentifier</key><string>$bundle_id</string>
    <key>CFBundleName</key><string>sinete</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.0.0-dev</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

# Generate the entitlements (Secure Enclave key access requires the access group). Written to dist/
# (gitignored), so the team/bundle is never baked into a tracked file.
ent="dist/sinete.entitlements"
cat >"$ent" <<ENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key><string>$access_group</string>
    <key>keychain-access-groups</key><array><string>$access_group</string></array>
</dict>
</plist>
ENT

# Sign the bundle with the SE entitlements (codesign recurses into Contents/MacOS/sinete). The
# entitlement wall makes the keychain-access-group keys usable by this signed identity.
codesign --force --sign "$identity" \
    --entitlements "$ent" \
    --options runtime \
    "$app"

echo "--- signed; verifying ---"
codesign -dvvv "$app" 2>&1 | grep -iE "TeamIdentifier|Authority=Apple" || true
codesign --verify --deep --strict --verbose=2 "$app"
echo "--- entitlements ---"
codesign -d --entitlements :- "$app" 2>/dev/null | grep -iE "keychain-access-groups|application-identifier" || true
echo "OK: $app"
