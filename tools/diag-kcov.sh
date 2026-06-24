#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Diagnose the freshly-built kcov: is it still AVX-512 + is its first __text
# function's prologue corrupt? Builds the dependency via `zig build`, locates the
# kcov binary, dumps the evidence, and uploads it. No typing required.
set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here" || { echo "cannot cd to repo root $here"; exit 1; }

echo "==> building kcov dependency (zig build) ..."
zig build 2>&1 | tail -3

# Find the most-recently-built Mach-O executable named kcov across caches.
gcache="$(zig env 2>/dev/null | perl -ne 'print $1 if /"global_cache_dir":\s*"([^"]+)"/')"
dirs=(".zig-cache"); [ -n "$gcache" ] && [ -d "$gcache" ] && dirs+=("$gcache")
K=""
for d in "${dirs[@]}"; do
  while IFS= read -r f; do
    case "$(file -b "$f" 2>/dev/null)" in *Mach-O*executable*) printf '%s\t%s\n' "$(stat -f '%m' "$f")" "$f";; esac
  done < <(find "$d" -type f -name kcov 2>/dev/null)
done | sort -rn | head -1 | { read -r _ K; echo "$K"; } > /tmp/kpath
K="$(cat /tmp/kpath)"

rep="/tmp/kcov-diag.txt"
{
  echo "### kcov diagnosis  $(date)"
  echo "# host=$(uname -m) os=$(uname -r) sdk=$(xcrun --show-sdk-version 2>/dev/null)"
  echo "# kcov: $K"
  [ -n "$K" ] && [ -f "$K" ] || { echo "ERROR: kcov binary not found"; exit 0; }
  echo
  echo "## LC_BUILD_VERSION:"
  otool -l "$K" 2>/dev/null | grep -A4 LC_BUILD_VERSION | grep -E 'minos|sdk'
  echo
  echo "## AVX-512 instruction count (expect 0 if the baseline fix took):"
  n="$(otool -tvV "$K" 2>/dev/null | grep -ciE '%zmm|%k[1-7]|vpxord|vpternlog|vmovdqu(8|16|32|64)|vpbroadcast.*%zmm')"
  echo "AVX512_COUNT=$n"
  echo "## a few AVX-512 sites (if any):"
  otool -tvV "$K" 2>/dev/null | grep -iE '%zmm|%k[1-7]|vpternlog|vmovdqu64' | head -5
  echo
  echo "## collectStmtAddrs prologue (clean = 'pushq %rbp; ...; pushq %r15'):"
  otool -tvV "$K" 2>/dev/null | awk '/dwarf\.collectStmtAddrs:/{f=1} f{print; c++} c>9{exit}'
  echo
  echo "## any AVX-512 inside collectStmtAddrs itself?"
  otool -tvV "$K" 2>/dev/null | awk '/dwarf\.collectStmtAddrs:/{f=1} f&&/^_dwarf\.emitRows:/{exit} f' \
    | grep -ciE '%zmm|%k[1-7]|vpternlog|vmovdqu64' | sed 's/^/AVX512_IN_FN=/'
} > "$rep" 2>&1

echo "==> uploading $rep ..."
cat "$rep" | nc termbin.com 9999
echo
echo "==> (also printed above is the termbin URL). Send it to me."
