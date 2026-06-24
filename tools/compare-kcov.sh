#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Standalone kcov-zig (ReleaseFast) builds CLEAN, but sinete's dependency build of
# the same recipe is CORRUPT on the same machine. Build BOTH, report minos +
# prologue for each, and upload both binaries so they can be diffed to find the
# difference (suspect: a malformed deployment target / os_version_min). No typing.
set -u

ZIG="${1:-}"
if [ -z "$ZIG" ]; then
  for c in "$HOME/Downloads/zig-x86_64-macos-0.16.0/zig" "$(command -v zig 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && { ZIG="$c"; break; }
  done
fi
[ -n "$ZIG" ] && [ -x "$ZIG" ] || { echo "usage: $0 /path/to/zig"; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

prologue() { otool -tvV "$1" 2>/dev/null | awk '/dwarf\.collectStmtAddrs:/{f=1;getline;print;exit}'; }
minos()    { otool -l "$1" 2>/dev/null | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $2; exit}'; }

# --- A: standalone kcov-zig (the CLEAN case) ---
work="/tmp/kcov-standalone-build"
if [ -d "$work/.git" ]; then git -C "$work" fetch origin debug-hang 2>/dev/null; git -C "$work" reset --hard origin/debug-hang 2>/dev/null
else rm -rf "$work"; git clone --branch debug-hang https://github.com/paulofduarte/kcov "$work" 2>&1 | tail -1; fi
( cd "$work" && rm -rf .zig-cache zig-out && echo "==> building STANDALONE kcov ..." && "$ZIG" build -Doptimize=ReleaseFast 2>&1 | tail -2 )
A="$work/zig-out/bin/kcov"

# --- B: sinete dependency build (the CORRUPT case) ---
cd "$here" && echo "==> building DEPENDENCY kcov via sinete ..." && "$ZIG" build 2>&1 | tail -2
gcache="$("$ZIG" env 2>/dev/null | perl -ne 'print $1 if /"global_cache_dir":\s*"([^"]+)"/')"
B=""
for d in ".zig-cache" "$gcache"; do
  [ -d "$d" ] || continue
  while IFS= read -r f; do
    case "$(file -b "$f" 2>/dev/null)" in *Mach-O*executable*) printf '%s\t%s\n' "$(stat -f '%m' "$f")" "$f";; esac
  done < <(find "$d" -type f -name kcov 2>/dev/null)
done | sort -rn | head -1 | { read -r _ p; echo "$p"; } > /tmp/bpath
B="$(cat /tmp/bpath)"

echo
echo "================= SUMMARY ================="
echo "STANDALONE  minos=$(minos "$A")  prologue: $(prologue "$A")"
echo "DEPENDENCY  minos=$(minos "$B")  prologue: $(prologue "$B")"
echo "==========================================="
echo "==> uploading both binaries ..."
echo "STANDALONE URL: $(curl -fsS -F"file=@$A" https://0x0.st 2>/dev/null)"
echo "DEPENDENCY URL: $(curl -fsS -F"file=@$B" https://0x0.st 2>/dev/null)"
echo "==> send me both URLs + the SUMMARY block above."
