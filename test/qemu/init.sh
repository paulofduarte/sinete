#!/bin/busybox sh
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Guest /init for the QEMU+swtpm integration test (run.sh assembles it into an
# initramfs). Exercises the Linux TPM backend end-to-end against the software TPM at
# /dev/tpmrm0, then powers off. Prints SINETE_VM_PASS iff every step succeeded; the
# host run.sh greps for that marker.

/bin/busybox mkdir -p /proc /sys /dev /tmp /data/config
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
/bin/busybox --install -s /bin
export HOME=/root XDG_DATA_HOME=/data XDG_CONFIG_HOME=/data/config PATH=/bin

fail=0
run() {
  label=$1
  shift
  echo "--- $label ---"
  "$@"
  rc=$?
  echo "[rc=$rc] $label"
  [ "$rc" -eq 0 ] || fail=1
}

if [ ! -e /dev/tpmrm0 ]; then
  echo "FATAL: /dev/tpmrm0 missing (no TPM)"
  fail=1
fi

# _enclave-check: enumerate, provision the master key + epoch NV counter, master
# sign+verify, signed-config round-trip (NV increments) and tamper-reject.
run "enclave-check" sinete _enclave-check
# user key create + enumerate via sks/diskio.
run "generate" sinete generate vmtest
run "list" sinete list
# config writes advance the epoch NV counter (Config.Save -> Increment).
run "config-presence-ttl" sinete config set presence-ttl 10m
run "config-presence-max-ttl" sinete config set presence-max-ttl 2h

if [ "$fail" -eq 0 ]; then
  echo "SINETE_VM_PASS"
else
  echo "SINETE_VM_FAIL"
fi
/bin/busybox poweroff -f
