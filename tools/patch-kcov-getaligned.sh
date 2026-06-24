#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# LOCAL VALIDATION patch: SimonKagstrom/kcov's mach-engine.cc defines
#   getAligned(uint32_t addr)
# which truncates 64-bit breakpoint addresses. On macOS (image base
# 0x100000000) that makes `8 * (addr - getAligned(addr))` blow up to
# 0x800000000 -- the Debug-build "shift exponent too large" panic, and a
# wrong <4GB poke in Release. Widen it to 64-bit in the package cache so the
# Debug-mode kcov coverage path can be validated end-to-end before we land the
# real fix as a pinned kcov fork. Re-run after any `zig fetch`.
set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here" || { echo "cannot cd to repo root $here"; exit 1; }

gcache="$(zig env 2>/dev/null | perl -ne 'print $1 if /"global_cache_dir":\s*"([^"]+)"/')"
search_dirs=("$here/zig-pkg" ".zig-cache")
[ -n "$gcache" ] && search_dirs+=("$gcache/p" "$gcache")

found=0
for d in "${search_dirs[@]}"; do
  [ -d "$d" ] || continue
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    found=1
    if grep -q 'getAligned(unsigned long addr)' "$f"; then
      echo "already patched: $f"
      continue
    fi
    chmod u+w "$f" 2>/dev/null || true
    perl -0pi -e 's/constexpr\s+uint32_t\s*\n\s*getAligned\(uint32_t addr\)/constexpr unsigned long\ngetAligned(unsigned long addr)/s' "$f"
    if grep -q 'getAligned(unsigned long addr)' "$f"; then
      echo "patched: $f"
    else
      echo "WARN: pattern not found (already changed upstream?) in $f"
      grep -n 'getAligned' "$f" | head
    fi
  done < <(find "$d" -type f -name 'mach-engine.cc' 2>/dev/null)
done

[ "$found" = 1 ] || { echo "ERROR: no mach-engine.cc found in: ${search_dirs[*]}"; exit 1; }

echo
echo "==> Patched. Now build + run coverage (x86_64-macOS kcov is built as Debug):"
echo "    zig build coverage"
