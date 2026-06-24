#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Empirical A/B for the kcov getAligned fix. The patch script edits the cached
# kcov source in place and it STAYS patched across runs, so "running without the
# patch" doesn't actually test the unpatched code. This forces the cached
# mach-engine.cc to each state, rebuilds, runs coverage, and reports both -- so you
# can see the unpatched (uint32_t) build fail/miscount and the patched
# (unsigned long) build produce real coverage. Leaves the source PATCHED at the end.
set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$here" || exit 1

# Locate the cached mach-engine.cc (compiled by the kcov dependency build).
gcache="$(zig env 2>/dev/null | perl -ne 'print $1 if /"global_cache_dir":\s*"([^"]+)"/')"
F=""
for d in "$here/zig-pkg" ".zig-cache" "$gcache/p" "$gcache"; do
  [ -d "$d" ] || continue
  f="$(find "$d" -type f -name 'mach-engine.cc' 2>/dev/null | head -1)"
  [ -n "$f" ] && { F="$f"; break; }
done
[ -n "$F" ] || { echo "mach-engine.cc not found -- run 'zig build' once first."; exit 1; }
echo "cached kcov source: $F"

set_uint32() { chmod u+w "$F" 2>/dev/null; perl -0pi -e 's/constexpr unsigned long\s*\n\s*getAligned\(unsigned long addr\)/constexpr uint32_t\ngetAligned(uint32_t addr)/s' "$F"; }
set_ulong()  { chmod u+w "$F" 2>/dev/null; perl -0pi -e 's/constexpr uint32_t\s*\n\s*getAligned\(uint32_t addr\)/constexpr unsigned long\ngetAligned(unsigned long addr)/s' "$F"; }
cov_pct() { # best-effort: pull a coverage figure out of kcov-out
  { find kcov-out -name 'coverage.json' -exec grep -ho '"percent_covered"[^,}]*' {} \; 2>/dev/null
    find kcov-out -name 'cobertura.xml' -exec grep -ho 'line-rate="[0-9.]*"' {} \; 2>/dev/null; } | head -3 | tr '\n' ' '
}

run() { # $1 = label ; sets exit code into RC, output into OUT, coverage into PCT
  rm -rf kcov-out
  zig build coverage > "/tmp/cov-$1.txt" 2>&1; RC=$?
  PCT="$(cov_pct)"
}

echo
echo "############### A: UNPATCHED  getAligned(uint32_t) ###############"
set_uint32; grep -n 'getAligned(' "$F" | head -1
run A
echo "--- last lines ---"; tail -8 "/tmp/cov-A.txt"
echo "coverage-step exit=$RC   kcov-out coverage: ${PCT:-<none>}"
A_RC=$RC; A_PCT="$PCT"

echo
echo "############### B: PATCHED    getAligned(unsigned long) ###############"
set_ulong; grep -n 'getAligned(' "$F" | head -1
run B
echo "--- last lines ---"; tail -8 "/tmp/cov-B.txt"
echo "coverage-step exit=$RC   kcov-out coverage: ${PCT:-<none>}"
B_RC=$RC; B_PCT="$PCT"

echo
echo "===================== VERDICT ====================="
echo "UNPATCHED (uint32_t)     : exit=$A_RC  coverage=${A_PCT:-<none>}"
echo "PATCHED   (unsigned long): exit=$B_RC  coverage=${B_PCT:-<none>}"
echo "(source left PATCHED). If A failed/zero and B passed/non-zero, getAligned is load-bearing."