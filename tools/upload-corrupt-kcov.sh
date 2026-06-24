#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# The x86_64-macOS Mach-O linker prologue corruption is environment-sensitive: it
# reproduces on the macOS 14.x SDK but NOT on a newer SDK, so it can't be built on
# every machine. This builds the kcov-zig recipe standalone (ReleaseFast) with the
# given Zig and, if collectStmtAddrs is corrupt, uploads the binary + structure so
# it can be diffed against a known-clean reference to pinpoint the corruptor.
#
# Usage: ./tools/upload-corrupt-kcov.sh [/path/to/zig]
#   (defaults to ~/Downloads/zig-x86_64-macos-0.16.0/zig, else `zig` on PATH)
set -u

ZIG="${1:-}"
if [ -z "$ZIG" ]; then
  for c in "$HOME/Downloads/zig-x86_64-macos-0.16.0/zig" "$(command -v zig 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && { ZIG="$c"; break; }
  done
fi
[ -n "$ZIG" ] && [ -x "$ZIG" ] || { echo "usage: $0 /path/to/zig"; exit 2; }
echo "==> zig: $("$ZIG" version 2>&1)  ($ZIG)"
echo "==> sdk: $(xcrun --show-sdk-version 2>&1)   host: $(uname -m)   os: $(uname -r)"

work="/tmp/kcov-linker-test"
if [ -d "$work/.git" ]; then
  git -C "$work" fetch origin debug-hang 2>&1 | tail -1
  git -C "$work" reset --hard origin/debug-hang 2>&1 | tail -1
else
  rm -rf "$work"
  git clone --branch debug-hang https://github.com/paulofduarte/kcov "$work" 2>&1 | tail -2
fi
cd "$work" || exit 1
rm -rf .zig-cache zig-out

echo "==> building kcov (native x86_64-macOS, ReleaseFast) ..."
"$ZIG" build -Doptimize=ReleaseFast 2>&1 | tail -6
B="zig-out/bin/kcov"
[ -x "$B" ] || { echo "BUILD FAILED"; exit 1; }

first="$(otool -tvV "$B" 2>/dev/null | awk '/dwarf\.collectStmtAddrs:/{f=1;next} f{print;exit}')"
echo "==> collectStmtAddrs first instruction: [$first]"
case "$first" in
  *pushq*%rbp*) echo ">>> CLEAN on this machine too — the corruption did NOT reproduce here. Nothing to upload.";;
  *) echo ">>> CORRUPT — this is the repro. Capturing + uploading.";;
esac

# Structure dump (small) to diff against the clean reference.
rep="/tmp/kcov-corrupt-structure.txt"
{
  echo "### CORRUPT (this machine): sdk $(xcrun --show-sdk-version) os $(uname -r)"
  echo "## LC_BUILD_VERSION:"; otool -l "$B" 2>/dev/null | grep -A4 LC_BUILD_VERSION | grep -E 'minos|sdk'
  echo "## sections:"
  otool -l "$B" 2>/dev/null | awk '/sectname/{s=$2} /^ *size/{print s, $0}' | grep -E '__text|__stubs|__got|__la_|__const|__cstring|__unwind|__data' | head -30
  echo "## collectStmtAddrs first 12 instrs:"
  otool -tvV "$B" 2>/dev/null | awk '/dwarf\.collectStmtAddrs:/{f=1} f{print; n++} n>13{exit}'
  echo "## raw first 48 bytes of collectStmtAddrs (file offset 0x9c0-ish; from nm):"
  addr="$(nm -n "$B" 2>/dev/null | awk '/dwarf\.collectStmtAddrs/{print $1; exit}')"
  echo "addr=$addr"
} > "$rep" 2>&1

echo "==> uploading binary + structure to 0x0.st ..."
echo "BINARY URL:    $(curl -fsS -F"file=@$B" https://0x0.st 2>/dev/null)"
echo "STRUCTURE URL: $(curl -fsS -F"file=@$rep" https://0x0.st 2>/dev/null)"
echo "==> send me both URLs."
