#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Shared guest test driver for the distro e2e matrix (run-full.sh). Runs in a LOCAL
# autologin (systemd-logind / elogind) session, with the REAL non-bypassed sinete at
# /root/sinete. It is distro-agnostic; per-distro differences (package manager, init,
# pinentry binary names) live in the sourced /root/distro.sh shim.
#
# Prints SINETE_VM_PASS iff every scenario passed; run-full.sh greps the serial log.
exec >/dev/console 2>&1
set -u

modprobe tpm_crb 2>/dev/null || true
modprobe tpm_tis 2>/dev/null || true
# Give the TPM device a moment to appear (udev race right after boot).
for _ in 1 2 3 4 5; do
  [ -e /dev/tpmrm0 ] && break
  sleep 1
done

# Alpine's first boot runs on the TPM-less linux-virt kernel and reboots into linux-lts
# (see distro-alpine.sh); the post-reboot autologin runs us for real. Bound the wait: if
# the TPM is still absent on the SECOND boot, the kernel swap failed — fail fast rather
# than idle at the autologin prompt until the host-side `timeout` kills QEMU.
if [ ! -e /dev/tpmrm0 ]; then
  n=$(cat /root/.notpm 2>/dev/null || echo 0)
  n=$((n + 1))
  echo "$n" >/root/.notpm
  if [ "$n" -ge 2 ]; then
    echo "FATAL: /dev/tpmrm0 still absent on boot $n (kernel $(uname -r)) — the TPM-capable (lts) kernel did not come up"
    echo "SINETE_VM_FAIL"
    poweroff -f 2>/dev/null || systemctl poweroff -f 2>/dev/null || true
    exit 1
  fi
  echo "DRIVER: no /dev/tpmrm0 on boot $n (kernel $(uname -r)) — awaiting the TPM-capable reboot"
  exit 0
fi
[ -f /root/.driver-ran ] && exit 0
touch /root/.driver-ran

# shellcheck source=/dev/null
. /root/distro.sh

echo "=== SINETE E2E DRIVER  distro=$DISTRO  kernel=$(uname -r)  $(date +%T) ==="
# Wait until provisioning (package install, services, autologin) has finished. If it
# never does, fail fast with a clear marker rather than running scenarios on a half-set-
# up guest (which would produce misleading failures).
for _ in $(seq 1 120); do
  [ -f /root/.provisioned ] && break
  sleep 2
done
if [ ! -f /root/.provisioned ]; then
  echo "FATAL: provisioning did not complete (/root/.provisioned missing) — see distro_provision output above"
  echo "SINETE_VM_FAIL"
  poweroff -f 2>/dev/null || systemctl poweroff -f 2>/dev/null || true
  exit 1
fi

install -m 0755 /root/sinete /usr/local/bin/sinete
export XDG_DATA_HOME=/root/.local/share XDG_CONFIG_HOME=/root/.config
mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"
unset DISPLAY WAYLAND_DISPLAY GPG_TTY
PIN=1234
PASS=0
FAIL=0
ok() {
  PASS=$((PASS + 1))
  echo "RESULT OK   $1"
}
bad() {
  FAIL=$((FAIL + 1))
  echo "RESULT BAD  $1"
}
# A genuine local-session refusal, not some unrelated error.
REFUSE='remote session|local session|logind|elogind'

echo "--- logind/elogind sessions ---"
loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}' | while read -r s; do
  echo "  session $s: $(loginctl show-session "$s" -p Remote -p Type -p Class -p Service 2>/dev/null | tr '\n' ' ')"
done

# fake-pinentry feeds a fixed PIN non-interactively for the crypto phase.
fake_pinentry_on() {
  export GNUPGHOME=/root/.gnupg
  mkdir -p "$GNUPGHOME"
  echo "pinentry-program /root/fake-pinentry" >"$GNUPGHOME/gpg-agent.conf"
}
fake_pinentry_off() {
  unset GNUPGHOME
  rm -f /root/.gnupg/gpg-agent.conf
}

# expect drivers for the REAL pinentry programs / the x/term fallback. Per-dialog sends
# (matching the prompt precisely) — a greedy match floods ncurses redraws.
feed_line() { # $1 ttl  $2 create|sign
  expect <<-EXP
		set timeout 60
		spawn sinete config set presence-ttl $1
		if {"$2" == "create"} {
		  expect "New PIN:"; send -- "$PIN\r"
		  expect -re "Confirm"; send -- "$PIN\r"
		} else { expect -re "PIN:"; send -- "$PIN\r" }
		catch {expect eof}
		catch wait r; exit [lindex \$r 3]
	EXP
}
feed_curses() { # $1 ttl
  expect <<-EXP
		set timeout 60
		spawn env TERM=xterm sinete config set presence-ttl $1
		expect -re "PIN"
		after 1200
		send -- "$PIN\r"
		catch {expect eof}
		catch wait r; exit [lindex \$r 3]
	EXP
}
feed_wrong() { # a wrong PIN must be rejected by the TPM
  expect <<-EXP
		set timeout 60
		spawn sinete config set presence-ttl 9m
		expect -re "PIN:"; send -- "9999\r"
		catch {expect eof}
		catch wait r; exit [lindex \$r 3]
	EXP
}

stash=/root/pinentry-stash
mkdir -p "$stash"
pin_hide() { [ -e "/usr/bin/$1" ] && mv "/usr/bin/$1" "$stash/$1"; }
pin_restore() { [ -e "$stash/$1" ] && mv "$stash/$1" "/usr/bin/$1"; }

ssh_setup() {
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519 >/dev/null 2>&1
  cat /root/.ssh/id_ed25519.pub >>/root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
}
ssh_run() { # $1 ttl — run a config write over a REMOTE (ssh) session
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes root@localhost \
    "XDG_DATA_HOME=$XDG_DATA_HOME XDG_CONFIG_HOME=$XDG_CONFIG_HOME /usr/local/bin/sinete config set presence-ttl $1" 2>&1
}

# ── [1] fail-closed: an unreachable system bus ⇒ refused EARLY (before the TPM). This
#       simulates "no logind/elogind" without disturbing the running services.
echo "--- [1] fail-closed (unreachable bus) ---"
out=$(DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent-bus sinete config set presence-ttl 5m 2>&1)
rc=$?
echo "  rc=$rc :: $(echo "$out" | tail -1)"
if [ $rc -ne 0 ] && echo "$out" | grep -qiE "$REFUSE"; then ok "fail-closed refused"; else bad "fail-closed NOT refused"; fi

# ── [2] remote (ssh) CREATE path — no master key yet ⇒ refused before creating it.
ssh_setup
echo "--- [2] remote create-path refused ---"
out=$(ssh_run 6m)
rc=$?
echo "  rc=$rc :: $(echo "$out" | tail -1)"
if [ $rc -ne 0 ] && echo "$out" | grep -qiE "$REFUSE"; then ok "remote create-path refused"; else bad "remote create-path NOT refused"; fi

# ── [3] _enclave-check: the TPM crypto backend (master sign/verify, NV counter,
#       signed-config round-trip, tamper-reject). Uses fake-pinentry. Creates the master.
echo "--- [3] _enclave-check (TPM crypto backend) ---"
fake_pinentry_on
ec_out=$(sinete _enclave-check 2>&1)
ec_rc=$?
echo "$ec_out" | tail -3
if [ $ec_rc -eq 0 ]; then ok "_enclave-check (TPM crypto)"; else bad "_enclave-check"; fi

# Provision a PERSISTENT master key (via fake-pinentry) for the SIGN scenarios below —
# _enclave-check is a self-test that removes the key it creates. This also sets
# presence-max-ttl, silencing the "unset" note. The create caches the PIN for the
# immediate sign, so it is 2 fake prompts here and the later real-pinentry writes are
# single SIGN prompts.
echo "--- provision persistent master key (fake-pinentry) ---"
prov_out=$(sinete config set presence-max-ttl 2h 2>&1)
prov_rc=$?
echo "PROV(rc=$prov_rc): $prov_out"
[ -e "$XDG_DATA_HOME/sks/sinete-_master" ] && echo "PROV: master blob present" || echo "PROV: master blob ABSENT"
fake_pinentry_off

# ── [4]–[6] each REAL pinentry program / the x/term fallback signs a config write.
echo "--- [4] pinentry-curses sign ---"
distro_expose_pinentry curses
if feed_curses 10m; then ok "pinentry-curses sign ($(distro_pinentry_curses))"; else bad "pinentry-curses sign"; fi

echo "--- [5] pinentry-tty sign ---"
distro_expose_pinentry tty
if feed_line 11m sign; then ok "pinentry-tty sign"; else bad "pinentry-tty sign"; fi

echo "--- [6] x/term fallback sign (no pinentry on PATH) ---"
distro_expose_pinentry none
if feed_line 12m sign; then ok "x/term fallback sign"; else bad "x/term fallback sign"; fi
distro_expose_pinentry all

# ── [7] a wrong PIN must be rejected by the TPM (proves the authValue actually gates).
echo "--- [7] wrong PIN rejected ---"
distro_expose_pinentry tty
feed_wrong
rc=$?
if [ $rc -ne 0 ]; then ok "wrong PIN rejected"; else bad "wrong PIN NOT rejected"; fi
distro_expose_pinentry all

# ── [8] remote (ssh) SIGN path — master exists now ⇒ refused before signing.
echo "--- [8] remote sign-path refused ---"
out=$(ssh_run 13m)
rc=$?
echo "  rc=$rc :: $(echo "$out" | tail -1)"
if [ $rc -ne 0 ] && echo "$out" | grep -qiE "$REFUSE"; then ok "remote sign-path refused"; else bad "remote sign-path NOT refused"; fi

echo "=== DRIVER DONE  distro=$DISTRO  pass=$PASS fail=$FAIL ==="
[ "$FAIL" -eq 0 ] && echo "SINETE_VM_PASS" || echo "SINETE_VM_FAIL"
sync
poweroff -f 2>/dev/null || systemctl poweroff -f 2>/dev/null || true
