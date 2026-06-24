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

# Zig prints the full failing argv when the child dies; pull the kcov command
# out of the log, from the kcov path through the trailing test-binary argument.
cmd="$(perl -ne 'print "$1\n" if m{(/\S+/kcov\s+.*?--include-pattern\S*\s+kcov-out\s+\S+)}' "$log" | tail -1)"

if [ -z "$cmd" ]; then
  echo "==> Could not parse the kcov argv from the log; scanning .zig-cache instead."
  kcov_bin="$(find .zig-cache -type f -name kcov -perm +111 2>/dev/null | head -1)"
  test_bin="$(find .zig-cache -type f -name test -perm +111 2>/dev/null | head -1)"
  cmd="$kcov_bin --clean --include-pattern=$here/lib,$here/src kcov-out $test_bin"
fi

# Paths in this project carry no spaces, so word-splitting the command is safe.
# shellcheck disable=SC2206
parts=($cmd)
kcov_bin="${parts[0]}"
kcov_args=("${parts[@]:1}")

echo "==> kcov binary: $kcov_bin"
echo "==> kcov args:   ${kcov_args[*]}"

if [ ! -x "$kcov_bin" ]; then
  echo "ERROR: kcov binary not found/executable: $kcov_bin"
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
