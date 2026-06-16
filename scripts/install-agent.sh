#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Install sinete's ssh-agent as a launchd user agent.
#
# A LaunchAgent runs in the user's Aqua (GUI) session, where macOS can present the
# Secure Enclave Touch ID prompt. The agent runs from the signed .app bundle at the
# path you give -- it is not moved or copied, so it works wherever the bundle lives.
#
# Usage: scripts/install-agent.sh [path-to-sinete.app]   (default: ./sinete.app)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${1:-$repo/sinete.app}"
[ -d "$src" ] || {
  echo "no app bundle at $src -- run scripts/bundle-and-sign.sh first" >&2
  exit 1
}
app="$(cd "$src" && pwd)" # resolve to an absolute path, wherever it lives
bin="$app/Contents/MacOS/sinete"
[ -x "$bin" ] || {
  echo "no runnable binary at $bin -- bundle looks incomplete; re-run scripts/bundle-and-sign.sh" >&2
  exit 1
}
wrapper="$repo/scripts/sinete-agent.sh"
chmod +x "$wrapper"

label="me.paulofduarte.sinete.agent"
run_dir="$HOME/Library/Caches/sinete"
sock="$run_dir/agent.sock"
log="$run_dir/agent.log"
plist="$HOME/Library/LaunchAgents/$label.plist"

mkdir -p "$run_dir" "$HOME/Library/LaunchAgents"
chmod 700 "$run_dir" # only the user may reach the agent socket

# Substitute paths into the plist's XML <string> nodes. XML-escape first (&, <, >)
# so special characters can't corrupt the XML, then escape sed replacement
# metacharacters (&, \, and the # delimiter).
esc() {
  printf '%s' "$1" |
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' |
    sed 's/[&\\#]/\\&/g'
}
sed -e "s#__WRAPPER__#$(esc "$wrapper")#" \
  -e "s#__BIN__#$(esc "$bin")#" \
  -e "s#__SOCKET__#$(esc "$sock")#" \
  -e "s#__LOG__#$(esc "$log")#" \
  "$repo/launchd/$label.plist" >"$plist"

uid="$(id -u)"
launchctl bootout "gui/$uid/$label" 2>/dev/null || true
launchctl bootstrap "gui/$uid" "$plist"

# Put `sinete` on PATH. The symlink resolves into the signed bundle, so the
# binary keeps its Secure Enclave entitlements.
link="/usr/local/bin/sinete"
if ln -sfn "$bin" "$link" 2>/dev/null || sudo ln -sfn "$bin" "$link" 2>/dev/null; then
  echo "linked:                $link"
else
  echo "could not link $link; run: sudo ln -sfn '$bin' '$link'"
fi

echo "installed and started: $plist"
echo "agent bundle:          $app"
echo "socket:                $sock"
echo
echo "The agent owns SSH_AUTH_SOCK for the session and delegates non-enclave keys"
echo "to your existing agent, so ssh/git use the enclave keys with no ~/.ssh/config"
echo "changes. Open a NEW terminal (or log out and back in) for it to take effect,"
echo "then check:  ssh-add -l"
