#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Install sinete's ssh-agent as a macOS login item via SMAppService.
#
# The agent's launchd plist is bundled inside the signed .app
# (Contents/Library/LaunchAgents). Registering it from the bundle makes macOS
# attribute the login item to sinete.app -- name + icon, not a stray script. The
# agent runs from wherever the bundle lives; it is not moved or copied.
#
# Usage: scripts/install-agent.sh [path-to-sinete.app]   (default: ./sinete.app)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${1:-$repo/sinete.app}"
[ -d "$src" ] || {
  echo "no app bundle at $src -- run 'nix run .#bundle -- <profile>' first" >&2
  exit 1
}
app="$(cd "$src" && pwd)" # resolve to an absolute path, wherever it lives
bin="$app/Contents/MacOS/sinete"
[ -x "$bin" ] || {
  echo "no runnable binary at $bin -- bundle looks incomplete; re-run 'nix run .#bundle -- <profile>'" >&2
  exit 1
}

# Register the bundled launchd agent as a login item (SMAppService). Run from the
# signed bundle so macOS validates it and attributes the item to the app.
"$bin" service register
echo "registered login item from: $app"
echo "status:                     $("$bin" service status || true)"

# Put `sinete` on PATH. The symlink resolves into the signed bundle, so the
# binary keeps its Secure Enclave entitlements.
link="/usr/local/bin/sinete"
if ln -sfn "$bin" "$link" 2>/dev/null || sudo ln -sfn "$bin" "$link" 2>/dev/null; then
  echo "linked:                     $link"
else
  echo "could not link $link; run: sudo ln -sfn '$bin' '$link'"
fi

echo
echo "The agent owns SSH_AUTH_SOCK for the session and delegates non-enclave keys"
echo "to your existing agent, so ssh/git use the enclave keys with no ~/.ssh/config"
echo "changes. Open a NEW terminal (or log out and back in), then check: ssh-add -l"
echo
echo "If System Settings > General > Login Items & Extensions shows sinete as"
echo "needing approval, enable it there (SMAppService may require a one-time OK)."
