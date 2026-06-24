#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Capture a full post-mortem of the kcov SIGSEGV on x86_64 macOS.
#
# Run it on the Intel Mac from the sinete-zig checkout:
#   ./tools/capture-kcov-crash.sh
# It provokes the crash (zig build coverage), extracts the exact kcov command
# the build ran, re-signs kcov so lldb can debug it, then dumps registers,
# backtrace and the faulting instruction to kcov-crash-report.txt. Send me that
# file -- it pins the instruction at collectStmtAddrs+5 that touches 0xf0000032.
set -u

# Repo root: this script lives in tools/, so root is one level up.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here" || { echo "cannot cd to repo root $here"; exit 1; }

log="/tmp/kcov-build.log"
report="$here/kcov-crash-report.txt"
ent="/tmp/kcov-debug.entitlements"
cmds="/tmp/kcov-lldb.cmds"

echo "==> Provoking the crash: zig build coverage (builds + signs kcov, runs it)"
zig build coverage 2>&1 | tee "$log"

# Zig's global cache dir also holds dependency build artifacts in some layouts.
gcache="$(zig env 2>/dev/null | perl -ne 'print $1 if /"global_cache_dir":\s*"([^"]+)"/')"
search_dirs=(".zig-cache")
[ -n "$gcache" ] && [ -d "$gcache" ] && search_dirs+=("$gcache")

# Find an executable Mach-O artifact by name across the cache dirs (no -perm:
# macOS find rejects "+111" on newer systems). Pick the most recent match.
find_macho() {
  local name="$1" f
  for d in "${search_dirs[@]}"; do
    while IFS= read -r f; do
      [ -f "$f" ] || continue
      case "$(file -b "$f" 2>/dev/null)" in
        *Mach-O*executable*) echo "$f" ;;
      esac
    done < <(find "$d" -type f -name "$name" 2>/dev/null)
  done | while IFS= read -r f; do printf '%s\t%s\n' "$(stat -f '%m' "$f" 2>/dev/null)" "$f"; done \
       | sort -rn | head -1 | cut -f2-
}

# Preferred: lift the exact failing argv from the build log (the line carrying
# the distinctive 'kcov-out' arg), trimmed to start at the kcov path.
cmd="$(grep -F 'kcov-out' "$log" | grep -F 'include-pattern' | tail -1 \
        | perl -pe 's{^.*?(/\S*/kcov\s)}{$1}')"

kcov_bin=""
kcov_args=()
if [ -n "$cmd" ]; then
  # Paths in this project carry no spaces, so word-splitting is safe.
  # shellcheck disable=SC2206
  parts=($cmd)
  kcov_bin="${parts[0]}"
  kcov_args=("${parts[@]:1}")
fi

# Fall back to reconstructing the command from cache artifacts.
if [ -z "$kcov_bin" ] || [ ! -x "$kcov_bin" ]; then
  echo "==> Argv not parsed from log; reconstructing from cache artifacts."
  kcov_bin="$(find_macho kcov)"
  test_bin="$(find_macho test)"
  kcov_args=( --clean "--include-pattern=$here/lib,$here/src" kcov-out "$test_bin" )
fi

echo "==> kcov binary: $kcov_bin"
echo "==> kcov args:   ${kcov_args[*]}"

if [ -z "$kcov_bin" ] || [ ! -x "$kcov_bin" ]; then
  {
    echo "# kcov crash post-mortem -- DISCOVERY FAILED"
    echo "# Could not locate the kcov executable. Diagnostics follow; send this file."
    echo
    echo "## search dirs: ${search_dirs[*]}"
    echo "## kcov candidates (name match, any type):"
    for d in "${search_dirs[@]}"; do find "$d" -name kcov 2>/dev/null; done
    echo "## test candidates:"
    for d in "${search_dirs[@]}"; do find "$d" -name test -type f 2>/dev/null | head -20; done
    echo
    echo "## last 40 lines of 'zig build coverage':"
    tail -40 "$log"
  } | tee "$report"
  echo
  echo "==> Discovery failed; send me: $report"
  exit 1
fi

# Re-sign kcov so lldb can control it: cs.debugger (kcov debugs its own child),
# get-task-allow (lldb attaches to kcov), disable-library-validation.
cat > "$ent" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.cs.debugger</key><true/>
  <key>com.apple.security.get-task-allow</key><true/>
  <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict>
</plist>
PLIST
codesign -s - -f --entitlements "$ent" "$kcov_bin" || {
  echo "ERROR: codesign of $kcov_bin failed"; exit 1; }

# lldb batch: run to the crash, then dump everything that pins the fault.
cat > "$cmds" <<'LLDB'
run
script print("===== STOP REASON / FAULTING THREAD =====")
thread info
script print("===== REGISTERS (scan for 0xf0000032) =====")
register read
script print("===== BACKTRACE (all threads) =====")
thread backtrace all
script print("===== INSTRUCTIONS AROUND PC ('->' is the faulting one) =====")
disassemble --pc --count 24
script print("===== MODULE / SLIDE AT PC =====")
image lookup -a $pc --verbose
script print("===== collectStmtAddrs SYMBOL =====")
image lookup -r -n collectStmtAddrs
script print("===== LOADED IMAGES (load addresses / slides) =====")
image list -o -f
script print("===== MEMORY REGION AT PC =====")
memory region $pc
quit
LLDB

echo "==> Running under lldb; writing $report"
{
  echo "# kcov crash post-mortem"
  echo "# date: $(date)"
  echo "# host: $(uname -msrv)"
  echo "# zig:  $(zig version 2>/dev/null)"
  echo "# kcov: $kcov_bin"
  echo "# args: ${kcov_args[*]}"
  echo
  /usr/bin/lldb -b -s "$cmds" -- "$kcov_bin" "${kcov_args[@]}"
} 2>&1 | tee "$report"

echo
echo "==> Done. Send me the contents of:"
echo "    $report"
