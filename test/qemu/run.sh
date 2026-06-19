#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# QEMU + swtpm integration test for the Linux TPM backend (step 7). Boots a real Linux
# kernel with a software TPM 2.0 at /dev/tpmrm0 and runs sinete's enclave backend
# end-to-end (init.sh) — the path that cannot be exercised by unit tests or the in-
# process simulator (e.g. the kernel resource-manager session behaviour).
#
# Needs `go` on PATH and `nix`. The kernel, busybox, qemu and swtpm are all SUBSTITUTED
# from the binary cache (downloaded, never built locally), so NO Linux builder is
# required — it runs on an aarch64 macOS dev box (x86_64 guest under TCG) and on an
# x86_64 CI runner (KVM when /dev/kvm is usable, else TCG). The sinete binary is built
# with Go's own cross-compiler (GOOS=linux GOARCH=amd64), also no Linux builder.

set -euo pipefail

NIXPKGS="github:NixOS/nixpkgs/nixos-26.05" # match flake.nix
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
export WORK
# shellcheck disable=SC2329  # invoked indirectly by the EXIT trap
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "== build static linux/amd64 sinete =="
(cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/sinete" ./cmd/sinete)

echo "== fetch prebuilt kernel + busybox (substituted from cache) =="
KERNEL="$(nix build --no-link --print-out-paths --system x86_64-linux "$NIXPKGS#linux")/bzImage"
BBOX="$(nix build --no-link --print-out-paths --system x86_64-linux "$NIXPKGS#pkgsStatic.busybox")/bin/busybox"
export KERNEL

echo "== assemble initramfs =="
mkdir -p "$WORK/irfs/bin"
cp "$BBOX" "$WORK/irfs/bin/busybox"
cp "$WORK/sinete" "$WORK/irfs/bin/sinete"
cp "$HERE/init.sh" "$WORK/irfs/init"
chmod +x "$WORK/irfs/bin/"* "$WORK/irfs/init"
(cd "$WORK/irfs" && find . | LANG=C cpio -o -H newc 2>/dev/null | gzip) >"$WORK/initramfs.cpio.gz"

# KVM only helps an x86_64 host; on the aarch64 Mac the x86_64 guest runs under TCG.
if [ "$(uname -m)" = "x86_64" ] && [ -w /dev/kvm ]; then
  ACCEL=kvm CPU=host
else
  ACCEL=tcg CPU=max
fi
export ACCEL CPU
echo "== boot (accel=$ACCEL cpu=$CPU) =="

# shellcheck disable=SC2016  # $WORK/$KERNEL/$ACCEL/$CPU are expanded by the inner bash (exported above), not here
nix shell "$NIXPKGS#qemu" "$NIXPKGS#swtpm" -c bash -c '
	set -e
	mkdir -p "$WORK/tpmstate"
	swtpm socket --tpm2 --tpmstate dir="$WORK/tpmstate" \
		--ctrl type=unixio,path="$WORK/swtpm-sock" --flags startup-clear &
	SWTPM_PID=$!
	sleep 1
	timeout 600 qemu-system-x86_64 \
		-machine q35 -accel "$ACCEL" -cpu "$CPU" -smp 2 -m 1024 -nographic \
		-kernel "$KERNEL" -initrd "$WORK/initramfs.cpio.gz" \
		-append "console=ttyS0 panic=1" \
		-chardev socket,id=chrtpm,path="$WORK/swtpm-sock" \
		-tpmdev emulator,id=tpm0,chardev=chrtpm \
		-device tpm-crb,tpmdev=tpm0
	kill "$SWTPM_PID" 2>/dev/null || true
' | tee "$WORK/boot.log"

echo "== verdict =="
if grep -q "SINETE_VM_PASS" "$WORK/boot.log"; then
  echo "PASS: Linux TPM backend e2e against swtpm"
  exit 0
fi
echo "FAIL: SINETE_VM_PASS marker not found"
echo "--- last 40 lines of guest output ---"
grep -vE '^\[' "$WORK/boot.log" | tail -40
exit 1
