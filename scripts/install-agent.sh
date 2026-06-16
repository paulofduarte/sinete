#!/usr/bin/env bash
# Install sinete's ssh-agent as a launchd user agent.
#
# A LaunchAgent runs in the user's Aqua (GUI) session, which is where macOS can
# present the Secure Enclave Touch ID prompt. The signed .app bundle is copied to
# ~/Applications so launchd has a stable, entitled binary to run.
#
# Usage: scripts/install-agent.sh [path-to-sinete.app]   (default: ./sinete.app)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src_app="${1:-$repo/sinete.app}"
[ -d "$src_app" ] || { echo "no app bundle at $src_app — run scripts/bundle-and-sign.sh first" >&2; exit 1; }

label="dev.sinete.agent"
app="$HOME/Applications/sinete.app"
bin="$app/Contents/MacOS/sinete"
run_dir="$HOME/Library/Caches/sinete"
sock="$run_dir/agent.sock"
log="$run_dir/agent.log"
plist="$HOME/Library/LaunchAgents/$label.plist"

mkdir -p "$HOME/Applications" "$run_dir" "$HOME/Library/LaunchAgents"
rm -rf "$app"
cp -R "$src_app" "$app"

sed -e "s#__BIN__#$bin#" -e "s#__SOCKET__#$sock#" -e "s#__LOG__#$log#" \
    "$repo/launchd/$label.plist" > "$plist"

uid="$(id -u)"
launchctl bootout "gui/$uid/$label" 2>/dev/null || true
launchctl bootstrap "gui/$uid" "$plist"

echo "installed and started: $plist"
echo "agent bundle:          $app"
echo "socket:                $sock"
echo
echo "Point ssh at it per host (~/.ssh/config) so it uses the enclave key:"
echo "  Host github.com"
echo "      IdentityAgent $sock"
echo "      IdentitiesOnly yes"
echo "      IdentityFile <your sinete public key file>"
