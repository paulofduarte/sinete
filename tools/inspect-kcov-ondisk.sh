#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Static (no-run) inspection of the kcov binary to decide whether the
# collectStmtAddrs+5 prologue corruption is on-disk (linker) or load-time (a
# stray dyld rebase/chained-fixup writing a pointer into __text). Produces small
# output; upload it with: curl -F'file=@kcov-ondisk-report.txt' https://0x0.st
set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here" || { echo "cannot cd to repo root $here"; exit 1; }
report="$here/kcov-ondisk-report.txt"

# Build kcov if missing (no run), then locate the Mach-O artifact across caches.
gcache="$(zig env 2>/dev/null | perl -ne 'print $1 if /"global_cache_dir":\s*"([^"]+)"/')"
search_dirs=(".zig-cache"); [ -n "$gcache" ] && [ -d "$gcache" ] && search_dirs+=("$gcache")
find_macho() {
  local name="$1" f
  for d in "${search_dirs[@]}"; do
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      case "$(file -b "$f" 2>/dev/null)" in *Mach-O*executable*) echo "$f";; esac
    done < <(find "$d" -type f -name "$name" 2>/dev/null)
  done | while IFS= read -r f; do printf '%s\t%s\n' "$(stat -f '%m' "$f" 2>/dev/null)" "$f"; done \
       | sort -rn | head -1 | cut -f2-
}
kcov_bin="$(find_macho kcov)"
if [ -z "$kcov_bin" ]; then
  echo "==> kcov not built yet; building (no run) ..."
  zig build 2>&1 | tail -5
  kcov_bin="$(find_macho kcov)"
fi
[ -n "$kcov_bin" ] || { echo "ERROR: could not locate the kcov binary"; exit 1; }

# Function vmaddr from the symbol table; __TEXT is at vmaddr 0x100000000, fileoff 0,
# so file offset = vmaddr - 0x100000000 for a normal Mach-O x86_64 PIE.
sym_line="$(nm "$kcov_bin" 2>/dev/null | grep 'dwarf.collectStmtAddrs' | head -1)"
vmaddr_hex="$(echo "$sym_line" | awk '{print $1}')"
vmaddr=$((16#${vmaddr_hex:-0}))
fileoff=$(( vmaddr - 0x100000000 ))

{
  echo "# kcov on-disk inspection"
  echo "# date: $(date)"
  echo "# kcov: $kcov_bin"
  echo "# collectStmtAddrs symbol: $sym_line"
  echo "# vmaddr=0x$vmaddr_hex  fileoff=0x$(printf '%x' "$fileoff")"
  echo

  echo "===== ON-DISK DISASSEMBLY of collectStmtAddrs (otool -tvV, first ~14 instrs) ====="
  echo "# If this shows  push rbp / push r15 / sub rsp,0x238  -> on-disk is CORRECT"
  echo "# (so the in-memory garbage is a load-time dyld fixup). If it shows 00 00 etc. -> linker wrote garbage."
  otool -tvV "$kcov_bin" 2>/dev/null \
    | awk '/dwarf\.collectStmtAddrs:/{f=1} f{print; n++} f&&/-0x64\(%rbp\)/{print "...(prologue end)"; exit} n>18{exit}'
  echo

  echo "===== RAW ON-DISK BYTES at collectStmtAddrs (file offset 0x$(printf '%x' "$fileoff"), 48 bytes) ====="
  echo "# Correct prologue starts: 55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec 38 02 00 00"
  if [ "$fileoff" -ge 0 ]; then
    dd if="$kcov_bin" bs=1 skip="$fileoff" count=48 2>/dev/null | xxd
  else
    echo "(could not compute file offset)"
  fi
  echo

  echo "===== DYLD FIXUPS targeting the collectStmtAddrs page (should be NONE in __text) ====="
  echo "# Any rebase/bind/fixup at an address in [0x$vmaddr_hex .. +0x40) is the smoking gun."
  if command -v dyld_info >/dev/null 2>&1; then
    echo "--- dyld_info -fixups (filtered) ---"
    dyld_info -fixups "$kcov_bin" 2>/dev/null | grep -iE "0x10000(09|0a)[0-9a-f]" | head -40
    echo "--- dyld_info -fixups in __TEXT (any) ---"
    dyld_info -fixups "$kcov_bin" 2>/dev/null | awk '/__TEXT/{t=1} /__DATA|__LINKEDIT/{t=0} t' | head -30
  fi
  echo "--- otool -fixup_chains (filtered) ---"
  otool -fixup_chains "$kcov_bin" 2>/dev/null | grep -iE "0x10000(09|0a)[0-9a-f]" | head -40
  echo

  echo "===== chained-fixups / rebase load commands present? ====="
  otool -l "$kcov_bin" 2>/dev/null | grep -iE 'LC_DYLD_CHAINED_FIXUPS|LC_DYLD_INFO|DYLD_CHAINED|cmd LC_' | grep -iE 'CHAINED|DYLD_INFO' | head
} | tee "$report"

echo
echo "==> Done. Upload it:  curl -F'file=@$report' https://0x0.st     (or termbin)"
