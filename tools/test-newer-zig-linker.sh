#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Test whether a newer Zig fixes the x86_64-macOS Mach-O linker bug that corrupts
# 16 bytes of a function prologue in the large kcov link. Builds the kcov-zig
# recipe standalone (ReleaseFast, the mode that corrupts) with the Zig you point
# at, then disassembles collectStmtAddrs's entry: a clean build starts with
# `pushq %rbp`; a corrupt one starts with `sbbl $0x10000000` / `addb %al,(%rax)`.
#
# Usage:
#   1) Download a newer Zig from https://ziglang.org/download (latest master, or
#      a 0.16.x point release) and unpack it, e.g. ~/Downloads/zig-x86_64-macos-<ver>/
#   2) ./tools/test-newer-zig-linker.sh ~/Downloads/zig-x86_64-macos-<ver>/zig
set -u

ZIG="${1:-}"
[ -n "$ZIG" ] && [ -x "$ZIG" ] || { echo "usage: $0 /path/to/newer/zig"; exit 2; }
echo "==> zig: $("$ZIG" version 2>&1)  ($ZIG)"

work="/tmp/kcov-linker-test"
if [ -d "$work/.git" ]; then
  git -C "$work" fetch origin debug-hang 2>&1 | tail -1
  git -C "$work" checkout -f debug-hang 2>/dev/null
  git -C "$work" reset --hard origin/debug-hang 2>&1 | tail -1
else
  rm -rf "$work"
  git clone --branch debug-hang https://github.com/paulofduarte/kcov "$work" 2>&1 | tail -2
fi
cd "$work" || exit 1

echo "==> building kcov (native x86_64-macOS, ReleaseFast) ..."
"$ZIG" build -Doptimize=ReleaseFast 2>&1 | tail -10
B="zig-out/bin/kcov"
if [ ! -x "$B" ]; then
  echo
  echo ">>> BUILD FAILED. If the errors are build.zig API mismatches, this Zig is"
  echo "    too new for the recipe (inconclusive for the linker bug); try a 0.16.x"
  echo "    point release instead. If they're something else, send me the tail."
  exit 1
fi

echo
echo "===== collectStmtAddrs prologue ====="
otool -tvV "$B" 2>/dev/null | awk '/dwarf\.collectStmtAddrs:/{f=1} f{print; n++} n>11{exit}'

first="$(otool -tvV "$B" 2>/dev/null | awk '/dwarf\.collectStmtAddrs:/{f=1;next} f{print;exit}')"
echo
case "$first" in
  *pushq*%rbp*)
    echo ">>> VERDICT: CLEAN  (entry is 'pushq %rbp') -> the linker bug is FIXED in this Zig."
    echo "    If clean, we bump the toolchain pin to this version." ;;
  *)
    echo ">>> VERDICT: CORRUPT (entry is not 'pushq %rbp': '$first') -> the linker bug PERSISTS."
    echo "    Try another version, or we move to shrinking kcov / shelving x86_64-macOS." ;;
esac
