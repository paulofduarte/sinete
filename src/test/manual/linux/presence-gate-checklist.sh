#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Manual, interactive checklist for the Linux local-session PRESENCE GATE — the
# logind/elogind "is this operation happening at the machine, or over SSH?" check that
# guards master-key PIN entry (internal/localsession; issue #22 / PR #21). It is the
# manual counterpart to the automated matrix in src/test/qemu: the gate's decision
# depends on the real session topology (local seat vs ssh vs mixed vs no-logind), which
# can only be judged by a human moving between real sessions. It runs on ANY local Linux
# machine — a VM or real hardware — and will extend naturally to biometric/fingerprint
# presence checks as those land.
#
# It does NOT automate the session setup — YOU put yourself in the right session
# (graphical desktop terminal, local VT, or SSH), then run the matching scenario here.
# For each one it prints the logind topology the gate sees, runs a presence-gated probe,
# and classifies the result (ALLOW / REFUSE-remote / REFUSE-unavailable) against what the
# scenario expects. The gate runs BEFORE the PIN prompt, so a refusal is immediate; on an
# ALLOW you'll get the real pinentry — type your PIN or cancel, we only grade the gate.
#
#   nix run .#presence-gate-checklist           # builds sinete + runs this (SINETE preset)
#   nix run .#presence-gate-checklist -- 4      # run scenario 4 directly
#
# Or invoke directly from a checkout (point SINETE at a built binary):
#   SINETE=./sinete ./presence-gate-checklist.sh        # menu + setup instructions
#   SINETE=./sinete ./presence-gate-checklist.sh 1      # run scenario 1
#   ./presence-gate-checklist.sh topology               # just dump the logind view
#
# Override the probe if `config set` isn't what you want:
#   PROBE_ARGS="_enclave-check" ./presence-gate-checklist.sh 1

set -u

SINETE="${SINETE:-./sinete}"
# A presence-gated write: it runs the local-session gate first, then (on allow) prompts
# for the master-key PIN. Idempotent enough to re-run across scenarios.
PROBE_ARGS="${PROBE_ARGS:-config set presence-ttl 30s}"

c_red=$'\033[31m'
c_grn=$'\033[32m'
c_yel=$'\033[33m'
c_dim=$'\033[2m'
c_off=$'\033[0m'

# --- scenario table: <expected> | <where to run it> | <preconditions> -----------------
# expected is one of: ALLOW | REFUSE_REMOTE | REFUSE_UNAVAIL
scn_expected() { case "$1" in
  1) echo ALLOW ;; 2) echo ALLOW ;;
  3) echo REFUSE_REMOTE ;; 4) echo REFUSE_REMOTE ;; 5) echo REFUSE_REMOTE ;;
  6) echo REFUSE_UNAVAIL ;;
  *) echo "?" ;; esac }
scn_where() { case "$1" in
  1) echo "the GRAPHICAL desktop terminal (gnome-terminal/konsole)" ;;
  2) echo "a LOCAL virtual console — switch with Ctrl+Alt+F3 and log in" ;;
  3) echo "an SSH session you opened INTO this machine" ;;
  4) echo "the GRAPHICAL desktop terminal" ;;
  5) echo "the SSH shell" ;;
  6) echo "the GRAPHICAL desktop terminal (the bus is faked, nothing is stopped)" ;;
  esac }
scn_pre() { case "$1" in
  1) echo "NO ssh session to this machine is open." ;;
  2) echo "NO ssh session to this machine is open." ;;
  3) echo "you are logged in over SSH." ;;
  4) echo "ALSO leave an SSH session into this machine open at the same time." ;;
  5) echo "the graphical desktop is ALSO logged in at the same time." ;;
  6) echo "nothing special — scenario 6 sets DBUS_SYSTEM_BUS_ADDRESS to an unreachable bus." ;;
  esac }

# --- the logind view the gate decides from -------------------------------------------
# IMPORTANT: the gate keys on the session logind maps THIS pid to (Manager.GetSessionByPID),
# NOT $XDG_SESSION_ID — an inherited env var that may name a session this pid isn't in. So
# mirror the gate's own D-Bus call (via busctl) instead of inferring from the environment:
# an "o <path>" reply means in-session (its Remote flag then decides); a NoSessionForPID
# error is the session-less fallback case (graphical terminal / systemd --user) that
# scenarios 1 and 4 exercise. $XDG_SESSION_ID is shown only as a hint. busctl/loginctl are
# the HOST's by design (they must talk to the running logind/elogind); they're best-effort
# context here — the verdict comes from sinete's own gate output, not from these.
topology() {
  echo "${c_dim}--- loginctl list-sessions (all sessions; context) ---${c_off}"
  loginctl list-sessions 2>/dev/null || echo "  (loginctl not on PATH — context only)"
  echo "${c_dim}--- GetSessionByPID($$): what the gate resolves for this process ---${c_off}"
  if command -v busctl >/dev/null 2>&1; then
    busctl call org.freedesktop.login1 /org/freedesktop/login1 \
      org.freedesktop.login1.Manager GetSessionByPID u "$$" 2>&1 | while IFS= read -r l; do echo "  $l"; done
  else
    echo "  (busctl not on PATH — install systemd's busctl to see logind's per-PID lookup)"
  fi
  echo "  \$XDG_SESSION_ID=${XDG_SESSION_ID:-unset}  (env hint only; the gate does not use it)"
}

# classify the probe output -> ALLOW | REFUSE_REMOTE | REFUSE_UNAVAIL | REFUSE_OTHER
classify() {
  if grep -qiE "needs systemd-logind or elogind" "$1"; then
    echo REFUSE_UNAVAIL
  elif grep -qiE "could not confirm a local-only session|presence-gated operation from a remote session" "$1"; then
    echo REFUSE_REMOTE
  elif grep -qiE "cannot confirm a local session" "$1"; then
    echo REFUSE_OTHER
  else echo ALLOW; fi
}

run_scenario() {
  local n="$1" expected where pre log got verdict
  expected="$(scn_expected "$n")"
  where="$(scn_where "$n")"
  pre="$(scn_pre "$n")"
  [ "$expected" = "?" ] && {
    echo "no such scenario: $n"
    return 2
  }

  echo
  echo "================ scenario $n ================"
  echo "  RUN THIS FROM : $where"
  echo "  PRECONDITION  : $pre"
  echo "  EXPECTED      : $expected"
  echo "============================================"
  read -r -p "Set up as above, then press Enter to run (Ctrl-C to abort)… " _
  echo
  topology
  echo
  echo "${c_dim}--- running: $SINETE $PROBE_ARGS ---${c_off}"

  log="$(mktemp "${TMPDIR:-/tmp}/sinete-checklist.XXXXXX")"
  if [ "$n" = "6" ]; then
    # Simulate "bus/logind unreachable" without stopping logind (which would log a
    # desktop user out). A bad bus address makes SystemBus() fail -> Unavailable -> refuse.
    # shellcheck disable=SC2086  # PROBE_ARGS is intentionally word-split into argv
    DBUS_SYSTEM_BUS_ADDRESS="unix:path=/nonexistent-sinete-bus" \
      "$SINETE" $PROBE_ARGS 2>&1 | tee "$log"
  else
    # shellcheck disable=SC2086
    "$SINETE" $PROBE_ARGS 2>&1 | tee "$log"
  fi

  got="$(classify "$log")"
  rm -f "$log"
  echo
  echo "  observed: $got"

  # Grade on the allow/refuse axis; note whether the refusal KIND matched too.
  case "$expected:$got" in
  ALLOW:ALLOW) verdict="${c_grn}PASS${c_off}  (gate allowed → reached the PIN/op)" ;;
  ALLOW:REFUSE_*) verdict="${c_red}FAIL${c_off}  (expected ALLOW but the gate refused)" ;;
  REFUSE_*:ALLOW) verdict="${c_red}FAIL${c_off}  (expected a refusal but the gate allowed)" ;;
  "$expected:$expected") verdict="${c_grn}PASS${c_off}  (refused, correct kind)" ;;
  REFUSE_*:REFUSE_*) verdict="${c_yel}PASS*${c_off} (refused, but a different kind than expected — check the message)" ;;
  *) verdict="${c_red}?${c_off}" ;;
  esac
  echo "  VERDICT : $verdict"
}

menu() {
  cat <<EOF
local-session presence-gate checklist — sinete=$SINETE  probe='$PROBE_ARGS'

Run each scenario FROM the session it names (the script can't move you between sessions).
After a REFUSE test, re-run scenario 1 to confirm a clean ALLOW once the ssh session is closed.

  1  ALLOW           graphical desktop terminal, no ssh open        (session-less, local-only)
  2  ALLOW           local virtual console (Ctrl+Alt+F3)            (in-session, Remote=false)
  3  REFUSE remote   from an ssh session                            (in-session, Remote=true)
  4  REFUSE remote   desktop terminal WHILE an ssh session is open  (mixed → fail closed)  <-- key test
  5  REFUSE remote   from the ssh shell, desktop also logged in     (in-session, Remote=true)
  6  REFUSE unavail  bus faked unreachable (nothing is stopped)     (logind unavailable)

  topology   dump the current loginctl view
  <n>        run scenario n

Scenario 4 is the security hardening from PR #21: a session-less local process must be
refused the moment the same user ALSO has a remote (ssh) session — it can't be attributed
to the local seat. Pass #1, open an ssh session, then run #4 → it should flip to refused.
EOF
}

case "${1:-}" in
"" | menu | help | -h | --help) menu ;;
topology) topology ;;
[1-6]) run_scenario "$1" ;;
*)
  echo "unknown: $1"
  echo
  menu
  exit 2
  ;;
esac
