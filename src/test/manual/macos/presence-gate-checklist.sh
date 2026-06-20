#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Manual, interactive checklist for the macOS PRESENCE gate — the Touch ID
# (LocalAuthentication) confirmation that guards Secure-Enclave key use, plus the agent's
# per-key presence window (TTL cache) and the remote-session refusal. It is the macOS
# counterpart of src/test/manual/linux/presence-gate-checklist.sh: the same checklist
# shape (per-scenario expected verdict + PASS/FAIL grading), but exercising Touch ID / SE
# paths a human must drive — Touch ID cannot be faked, so this is manual by construction
# (the gating *logic* is covered automatically by the Go unit tests in internal/agent).
#
# Tiers (the nix app wires $SINETE to the signed bundle binary, which can do all of them):
#   A  presence prompt      `sinete present`            — approve / cancel / passcode / -n
#   B  Secure Enclave        `sinete config set`, `_enclave-check` — master-key Touch ID
#   C  agent window + remote  the running sinete agent   — TTL cache, expiry, remote refuse
#
# Build the signed bundle ONCE, AT the Mac (building codesigns it, and codesign needs the
# local login-keychain session — it fails over ssh):
#   nix run .#presence-gate-checklist -- <profile>      # build + show the menu
#   nix run .#presence-gate-checklist -- <profile> A1   # build + run one scenario
# Then re-run scenarios WITHOUT a profile — no rebuild, no codesign. This is REQUIRED for
# C4, the remote test, which must run from an ssh session and only drives the running agent:
#   nix run .#presence-gate-checklist -- C4             # over ssh into this Mac
#
# Or directly (point SINETE at an already-built bundle binary):
#   SINETE=./dist/sinete.app/Contents/MacOS/sinete ./presence-gate-checklist.sh
#
# Tier C drives the *installed/running* agent via its socket (it can't be faked either);
# override with SINETE_AGENT_SOCK.

set -u

SINETE="${SINETE:-./dist/sinete.app/Contents/MacOS/sinete}"
AGENT_SOCK="${SINETE_AGENT_SOCK:-$HOME/Library/Caches/sinete/agent.sock}"
# Where B1 parks the presence TTL so C1/C2 have a known, short window to observe.
TTL="${SINETE_PRESENCE_TTL:-30s}"

c_red=$'\033[31m'
c_grn=$'\033[32m'
c_dim=$'\033[2m'
c_off=$'\033[0m'

# C2 waits out the TTL via integer-seconds arithmetic, so the value must be like "30s".
# Reject anything else up front (e.g. "1m" would break the wait and the expiry observation).
printf '%s' "$TTL" | grep -qE '^[0-9]+s$' || {
  echo "SINETE_PRESENCE_TTL must be integer seconds like '30s' (C2 waits that long); got '$TTL'" >&2
  exit 2
}

# --- scenario table -------------------------------------------------------------------
# kind is one of:
#   APPROVE   expect exit 0 after you approve the prompt
#   REFUSE    expect non-zero exit (you cancel, or the op is refused)
#   OBSERVE   exit can't tell prompt-from-silent; you confirm the observed behaviour
scn_kind() { case "$1" in
  A1 | A3 | A4 | B1 | B3) echo APPROVE ;;
  A2 | B2 | C4) echo REFUSE ;;
  C1 | C2 | C3) echo OBSERVE ;;
  *) echo "?" ;; esac }
scn_desc() { case "$1" in
  A1) echo "present → APPROVE Touch ID" ;;
  A2) echo "present → CANCEL the prompt" ;;
  A3) echo "present → use the passcode fallback (Enter Password)" ;;
  A4) echo "present -n 3 → approve three prompts in one run" ;;
  B1) echo "config set presence-ttl $TTL → APPROVE (master-key Touch ID; arms C1/C2)" ;;
  B2) echo "config set presence-ttl 45s → CANCEL (write must be refused)" ;;
  B3) echo "_enclave-check → APPROVE (full SE master sign/verify + config round-trip)" ;;
  C1) echo "agent: first signature prompts, a second within $TTL is SILENT (cache)" ;;
  C2) echo "agent: after $TTL idle, the next signature RE-PROMPTS (expiry)" ;;
  C3) echo "agent: a deleted+recreated key RE-AUTHS (window keyed by public key)" ;;
  C4) echo "agent: a REMOTE (ssh) peer signing is REFUSED (sessionIsRemote)" ;;
  esac }
scn_setup() { case "$1" in
  A1 | A2 | A3 | A4 | B1 | B2 | B3 | C1 | C2 | C3) echo "run locally, at the Mac (Touch ID reachable)." ;;
  C4) echo "build the bundle locally first, then ssh INTO this Mac and run it with no profile (scenario C4) from that ssh session." ;;
  esac }

need_sinete() {
  [ -x "$SINETE" ] || {
    echo "${c_red}no sinete binary at \$SINETE=$SINETE${c_off}"
    echo "  build the signed bundle:  nix run .#bundle -- <profile>"
    echo "  then re-run, e.g.:        SINETE=./dist/sinete.app/Contents/MacOS/sinete $0 $1"
    return 1
  }
}
need_agent() {
  [ -S "$AGENT_SOCK" ] || {
    echo "${c_red}no agent socket at $AGENT_SOCK${c_off} — install/start sinete first"
    echo "  (./dist/sinete.app/Contents/MacOS/sinete install), or set SINETE_AGENT_SOCK."
    return 1
  }
}
# ssh-add drives the Tier C agent signatures; without it those scenarios can't run, and a
# missing-tool exit (127) must not be mistaken for an agent refusal. Require it explicitly.
need_ssh() {
  command -v ssh-add >/dev/null 2>&1 || {
    echo "${c_red}ssh-add not found on PATH${c_off} — required for the Tier C agent scenarios"
    return 1
  }
  # -T (sign-test with a key) arrived in OpenSSH 8.0; an older ssh-add would reject it and
  # Tier C would mis-grade (e.g. C4 PASSes without ever attempting a signature). Probe it
  # directly: a missing flag prints "illegal option"/"unknown option"; a supported -T just
  # fails on the empty input (no Touch ID — /dev/null is not a key).
  if ssh-add -T /dev/null 2>&1 | grep -qiE 'illegal option|unknown option'; then
    echo "${c_red}this ssh-add has no -T (sign-test) option — needs OpenSSH >= 8.0${c_off}; Tier C can't drive an agent signature"
    return 1
  fi
}

# ssh-add -T signs a challenge with each listed key via the agent → triggers the presence
# path without needing a server. Optional $1 restricts the test to the key whose comment
# (the sinete key name) equals $1, so a scenario can target one specific key even when the
# agent advertises several. Three-way result so callers never confuse "could not even
# attempt" with "the agent refused":
#   0  the agent SIGNED
#   1  the agent was asked but did NOT sign (refused / signature failed) — the C4 case
#   2  could not attempt (agent advertised no matching keys)
agent_sign() {
  local keys rc want="${1:-}"
  keys="$(mktemp "${TMPDIR:-/tmp}/sinete-agentkeys.XXXXXX")"
  if [ -n "$want" ]; then
    # Keep only the line whose trailing comment field is exactly $want.
    SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L 2>/dev/null | awk -v w="$want" '$NF == w' >"$keys"
  else
    SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -L >"$keys" 2>/dev/null
  fi
  if ! [ -s "$keys" ]; then
    rm -f "$keys"
    echo "  (agent advertised no${want:+ matching} keys — generate one first: $SINETE generate <name>)" >&2
    return 2
  fi
  if SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -T "$keys" >/dev/null 2>&1; then rc=0; else rc=1; fi
  rm -f "$keys"
  return "$rc"
}

ask_yn() { # $1 prompt -> 0 yes / 1 no
  local a
  read -r -p "$1 [y/N] " a
  case "$a" in [yY]*) return 0 ;; *) return 1 ;; esac
}

grade() { # $1 kind  $2 exit-or-observed(0/1)  -> prints the PASS/FAIL verdict line
  case "$1:$2" in
  APPROVE:0) echo "  VERDICT: ${c_grn}PASS${c_off} (approved → exit 0)" ;;
  APPROVE:*) echo "  VERDICT: ${c_red}FAIL${c_off} (expected success but it failed/was declined)" ;;
  REFUSE:0) echo "  VERDICT: ${c_red}FAIL${c_off} (expected a refusal but it succeeded)" ;;
  REFUSE:*) echo "  VERDICT: ${c_grn}PASS${c_off} (refused, as expected)" ;;
  OBSERVE:0) echo "  VERDICT: ${c_grn}PASS${c_off} (you confirmed the expected behaviour)" ;;
  OBSERVE:*) echo "  VERDICT: ${c_red}FAIL${c_off} (observed behaviour did not match)" ;;
  esac
}

run_scenario() {
  local s="$1" kind
  kind="$(scn_kind "$s")"
  [ "$kind" = "?" ] && {
    echo "no such scenario: $s"
    return 2
  }
  echo
  echo "================ scenario $s ================"
  echo "  WHAT     : $(scn_desc "$s")"
  echo "  SETUP    : $(scn_setup "$s")"
  echo "  EXPECT   : $kind"
  echo "============================================"
  read -r -p "Ready? press Enter to run (Ctrl-C to abort)… " _
  echo

  local rc=1 a b r k out
  case "$s" in
  # ── Tier A: presence prompt (LocalAuthentication) — exit code is authoritative ──
  A1)
    need_sinete "$s" || return 1
    "$SINETE" present "checklist A1 — approve me"
    rc=$?
    ;;
  A2)
    need_sinete "$s" || return 1
    echo "${c_dim}When the prompt appears, CANCEL it.${c_off}"
    "$SINETE" present "checklist A2 — cancel me"
    rc=$?
    ;;
  A3)
    need_sinete "$s" || return 1
    echo "${c_dim}Click \"Enter Password\" and use your login passcode (device-owner fallback).${c_off}"
    "$SINETE" present "checklist A3 — use the passcode"
    rc=$?
    ;;
  A4)
    need_sinete "$s" || return 1
    "$SINETE" present -n 3 "checklist A4 — approve x3"
    rc=$?
    ;;

  # ── Tier B: Secure Enclave / master key ──
  B1)
    need_sinete "$s" || return 1
    "$SINETE" config set presence-ttl "$TTL"
    rc=$?
    [ $rc -eq 0 ] && echo "  presence-ttl now: $("$SINETE" config get presence-ttl 2>/dev/null)"
    ;;
  B2)
    need_sinete "$s" || return 1
    echo "${c_dim}CANCEL the Touch ID prompt — the config write must be refused.${c_off}"
    out="$("$SINETE" config set presence-ttl 45s 2>&1)"
    rc=$?
    echo "$out" | tail -2
    # Grade on the exit code alone: a declined Touch ID fails the master-key signature, so
    # saveConfig (cfg.Save) returns an error and `config set` exits non-zero. Do NOT grep the
    # text — the "signed config could not be verified" line is a pre-write READ warning that
    # also prints on a *successful* write, so matching it would mis-grade a success as refused.
    if [ "$rc" -eq 0 ]; then
      # It went through (you approved instead of cancelling): presence-ttl is now 45s, not
      # the $TTL B1 set, which would skew the C1/C2 window observations. Restore it.
      echo "${c_red}note: the write SUCCEEDED — presence-ttl is now 45s, not the $TTL from B1.${c_off}"
      echo "${c_red}      re-run B1 to restore the intended window before C1/C2.${c_off}"
    fi
    ;;
  B3)
    need_sinete "$s" || return 1
    "$SINETE" _enclave-check
    rc=$?
    ;;

  # ── Tier C: agent presence window + remote refusal ──
  C1)
    need_agent || return 1
    need_ssh || return 1
    echo "Signing once — APPROVE the Touch ID prompt:"
    agent_sign
    a=$?
    echo "Signing again immediately (should be SILENT — no prompt):"
    agent_sign
    b=$?
    if [ "$a" -ne 0 ] || [ "$b" -ne 0 ]; then
      echo "  ${c_red}a signature did not complete (first=$a second=$b) — cannot judge caching${c_off}"
      rc=1
    else
      ask_yn "Did the FIRST prompt, and the SECOND stay silent (within $TTL)?" && rc=0 || rc=1
    fi
    ;;
  C2)
    need_agent || return 1
    need_ssh || return 1
    echo "Waiting out the idle TTL ($TTL) so the window lapses…"
    sleep "$((10#${TTL%s} + 3))" # base-10 (10#) so a leading-zero TTL like 08s isn't read as octal
    echo "Signing again — it should RE-PROMPT:"
    agent_sign
    r=$?
    if [ "$r" -ne 0 ]; then
      echo "  ${c_red}the signature did not complete (=$r) — cannot judge the re-prompt${c_off}"
      rc=1
    else
      ask_yn "Did it re-prompt for Touch ID after the idle wait?" && rc=0 || rc=1
    fi
    ;;
  C3)
    need_sinete "$s" || return 1
    need_agent || return 1
    need_ssh || return 1
    k="checklist-c3-$$"
    echo "${c_dim}Using a throwaway key '$k' (created and removed here; your real keys are untouched).${c_off}"
    "$SINETE" generate "$k" >/dev/null 2>&1 || {
      echo "  could not create test key"
      return 1
    }
    echo "Sign with it — APPROVE:"
    agent_sign "$k" # target only the throwaway key, not whatever else the agent advertises
    a=$?
    echo "Deleting and recreating '$k' (same name, NEW key) — approve any prompts:"
    if ! "$SINETE" delete "$k" >/dev/null 2>&1 || ! "$SINETE" generate "$k" >/dev/null 2>&1; then
      # If delete/recreate failed, the next signature could hit the OLD key (or none), so
      # the "keyed by public key" check would be meaningless — abort instead of mis-grading.
      echo "  ${c_red}could not delete+recreate '$k' — cannot judge re-auth${c_off}"
      rc=1
    else
      echo "Sign again — it should RE-PROMPT (window is keyed by public key, which changed):"
      agent_sign "$k"
      b=$?
      if [ "$a" -ne 0 ] || [ "$b" -ne 0 ]; then
        echo "  ${c_red}a signature did not complete (first=$a second=$b) — cannot judge re-auth${c_off}"
        rc=1
      else
        ask_yn "Did the recreated key re-prompt (not silently reuse the old window)?" && rc=0 || rc=1
      fi
    fi
    "$SINETE" delete "$k" >/dev/null 2>&1 # clean up the throwaway (best effort)
    ;;
  C4)
    need_agent || return 1
    need_ssh || return 1
    echo "${c_dim}You should be in an ssh session into this Mac. Attempting an agent signature…${c_off}"
    agent_sign
    r=$?
    if [ "$r" -eq 2 ]; then
      echo "  ${c_red}agent advertised no keys — generate one first; cannot run C4${c_off}"
      return 1
    fi
    rc=$r # 0 = signed (FAIL: remote should be refused), 1 = refused (PASS)
    ;;
  esac

  echo
  if [ "$kind" = OBSERVE ]; then
    grade "$kind" "$([ "$rc" -eq 0 ] && echo 0 || echo 1)"
  else
    echo "  exit=$rc"
    grade "$kind" "$rc"
  fi
}

menu() {
  cat <<EOF
macOS presence-gate checklist — sinete=$SINETE  agent=$AGENT_SOCK

Touch ID can't be faked, so you drive each prompt; the script grades the result.
Run scenarios in order — B1 sets presence-ttl=$TTL, which C1/C2 then observe.

  Tier A — presence prompt (Touch ID via LocalAuthentication)
    A1  APPROVE   present → approve
    A2  REFUSE    present → cancel
    A3  APPROVE   present → passcode fallback
    A4  APPROVE   present -n 3

  Tier B — Secure Enclave / master key  (needs the signed bundle)
    B1  APPROVE   config set presence-ttl $TTL → approve   (arms C1/C2)
    B2  REFUSE    config set → cancel (write refused)
    B3  APPROVE   _enclave-check (full SE round-trip)

  Tier C — agent window + remote  (needs the running agent)
    C1  OBSERVE   first sign prompts, second within $TTL is silent
    C2  OBSERVE   after $TTL idle, next sign re-prompts
    C3  OBSERVE   deleted+recreated key re-auths (throwaway key)
    C4  REFUSE    remote ssh peer refused  ← run from an ssh session

  <id>   run one scenario (e.g. A1, C4)
  all-a | all-b   run a whole local tier in order

C4 is also the headless/remote-macOS test: ssh into this Mac and run \`… C4\`.
EOF
}

case "${1:-}" in
"" | menu | help | -h | --help) menu ;;
all-a)
  for s in A1 A2 A3 A4; do run_scenario "$s"; done
  ;;
all-b)
  for s in B1 B2 B3; do run_scenario "$s"; done
  ;;
A1 | A2 | A3 | A4 | B1 | B2 | B3 | C1 | C2 | C3 | C4) run_scenario "$1" ;;
*)
  echo "unknown: $1"
  echo
  menu
  exit 2
  ;;
esac
