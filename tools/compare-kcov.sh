#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Standalone kcov-zig (ReleaseFast) builds CLEAN, but sinete's dependency build of
# the same recipe is CORRUPT on the same machine. Build BOTH, print a SUMMARY
# (minos + prologue each), and ship both binaries to termbin as gzip+base64 text
# (debug info stripped to keep size down; __text -- where the corruption is -- is
# untouched). No typing, no 0x0.st.
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
upload_bin() { # $1=binary -> prints termbin URL of gzip+base64 of a stripped copy
  local b="$1" t="/tmp/$(basename "$1").stripped"
  cp "$b" "$t" 2>/dev/null; strip -S "$t" 2>/dev/null || true
  gzip -c "$t" | base64 | nc termbin.com 9999
}

# --- A: standalone kcov-zig (CLEAN case) ---
work="/tmp/kcov-standalone-build"
if [ -d "$work/.git" ]; then git -C "$work" fetch origin debug-hang 2>/dev/null; git -C "$work" reset --hard origin/debug-hang 2>/dev/null
else rm -rf "$work"; git clone --branch debug-hang https://github.com/paulofduarte/kcov "$work" 2>&1 | tail -1; fi
( cd "$work" && rm -rf .zig-cache zig-out && echo "==> building STANDALONE kcov ..." && "$ZIG" build -Doptimize=ReleaseFast 2>&1 | tail -2 )
A="$work/zig-out/bin/kcov"

# --- B: sinete dependency build (CORRUPT case) ---
cd "$here" && echo "==> building DEPENDENCY kcov via sinete ..." && "$ZIG" build 2>&1 | tail -2
gcache="$("$ZIG" env 2>/dev/null | perl -ne 'print $1 if /"global_cache_dir":\s*"([^"]+)"/')"
for d in ".zig-cache" "$gcache"; do
  [ -d "$d" ] || continue
  while IFS= read -r f; do
    case "$(file -b "$f" 2>/dev/null)" in *Mach-O*executable*) printf '%s\t%s\n' "$(stat -f '%m' "$f")" "$f";; esac
  done < <(find "$d" -type f -name kcov 2>/dev/null)
done | sort -rn | head -1 | { read -r _ p; echo "$p"; } > /tmp/bpath
B="$(cat /tmp/bpath)"

echo
echo "================= SUMMARY ================="
echo "STANDALONE  $A"
echo "   minos=$(minos "$A")  prologue: $(prologue "$A")"
echo "DEPENDENCY  $B"
echo "   minos=$(minos "$B")  prologue: $(prologue "$B")"
echo "==========================================="
echo
echo "==> uploading STANDALONE (gzip+base64 -> termbin) ..."
echo "STANDALONE_B64_URL: $(upload_bin "$A")"
echo "==> uploading DEPENDENCY ..."
echo "DEPENDENCY_B64_URL: $(upload_bin "$B")"
echo
echo "==> send me the SUMMARY block + both *_B64_URL lines."
