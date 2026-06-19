#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Distro e2e MATRIX (heavier than the hermetic busybox run.sh). Boots real cloud images
# — Debian (glibc / systemd-logind) and Alpine (musl / elogind) — under QEMU + swtpm and
# runs the full local-session + TPM matrix (src/test/qemu/full/driver.sh) on each:
# fail-closed refusal, remote(ssh)-refused on create & sign, _enclave-check TPM crypto,
# pinentry-curses/-tty/x-term signs, wrong-PIN rejection.
#
# NOT a per-build CI gate — it needs network (apt/apk) and is slow. Run on demand
# (`nix run .#e2e-linux-full`) or on releases. Needs `go`, `nix`, ~2 GB disk and net.
#
# Override the set with: DISTROS="debian" bash run-full.sh

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GOMOD="$(cd "$HERE/../../.." && pwd)" # src/
REPO="$(cd "$GOMOD/.." && pwd)"
DISTROS="${DISTROS:-debian alpine}"

NIXPKGS_REV="$(nix eval --raw --impure --expr "(builtins.fromJSON (builtins.readFile \"$REPO/flake.lock\")).nodes.nixpkgs.locked.rev")"
NIXPKGS="github:NixOS/nixpkgs/$NIXPKGS_REV"

CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/sinete-e2e"
mkdir -p "$CACHE"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sinete-e2e-full.XXXXXX")"
export WORK NIXPKGS
# shellcheck disable=SC2329
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "== build REAL static linux/amd64 sinete (no bypass tag) =="
(cd "$GOMOD" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$WORK/sinete" ./cmd/sinete)

emit_user_data() {
  cat <<-'UD'
		#cloud-config
		password: root
		chpasswd: { expire: false }
		runcmd:
		  - [ sh, -c, "mkdir -p /mnt/seed; for d in /dev/vdb /dev/vdb1 /dev/sr0 /dev/sdb /dev/sdb1; do mount -o ro $d /mnt/seed 2>/dev/null && [ -f /mnt/seed/driver.sh ] && break; umount /mnt/seed 2>/dev/null; done; cp /mnt/seed/driver.sh /mnt/seed/distro.sh /mnt/seed/sinete /mnt/seed/fake-pinentry /root/; chmod +x /root/driver.sh /root/sinete /root/fake-pinentry; . /root/distro.sh; distro_provision > /dev/console 2>&1" ]
	UD
}

fetch_image() { # $1 distro  -> echoes cached image path
  local d="$1" url sha img
  # Upstream cloud images, cached after first fetch. Debian rotates dated snapshots out,
  # so we track its stable `latest/` URL; Alpine keeps point releases (version-pinned).
  # Set sha to pin a specific image (verified); empty just warns — fine for this
  # manual/release-only run.
  case "$d" in
  debian)
    url="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
    sha=""
    ;;
  alpine)
    url="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/cloud/nocloud_alpine-3.21.2-x86_64-bios-cloudinit-r0.qcow2"
    sha=""
    ;;
  *)
    echo "FATAL: unknown distro $d" >&2
    exit 1
    ;;
  esac
  img="$CACHE/$(basename "$url")"
  if [ ! -f "$img" ]; then
    echo "== fetch $d image ($(basename "$url")) ==" >&2
    curl -fsSL -o "$img.part" "$url" && mv "$img.part" "$img"
  fi
  if [ -n "$sha" ]; then
    echo "$sha  $img" | sha256sum -c - >&2 || {
      echo "FATAL: $d image sha256 mismatch" >&2
      exit 1
    }
  else
    echo "WARN: $d image sha256 not pinned; got $(sha256sum "$img" | awk '{print $1}')" >&2
  fi
  echo "$img"
}

run_distro() { # $1 distro -> 0 pass / 1 fail
  local d="$1" img dir
  img="$(fetch_image "$d")"
  dir="$WORK/$d"
  mkdir -p "$dir/seed" "$dir/tpm"
  printf 'instance-id: sinete-%s\nlocal-hostname: sinete-%s\n' "$d" "$d" >"$dir/seed/meta-data"
  emit_user_data >"$dir/seed/user-data"
  cp "$HERE/driver.sh" "$dir/seed/driver.sh"
  cp "$HERE/distro-$d.sh" "$dir/seed/distro.sh"
  cp "$HERE/../fake-pinentry.sh" "$dir/seed/fake-pinentry"
  cp "$WORK/sinete" "$dir/seed/sinete"

  echo "== [$d] build vfat cidata seed + overlay ==" >&2
  nix shell "$NIXPKGS#mtools" "$NIXPKGS#coreutils" -c bash -c '
		truncate -s 96M "'"$dir"'/seed.img"
		mformat -i "'"$dir"'/seed.img" -v cidata -T 196608 ::
		mcopy -i "'"$dir"'/seed.img" "'"$dir"'/seed/"* ::' >&2
  nix shell "$NIXPKGS#qemu" -c qemu-img create -f qcow2 -F qcow2 -b "$img" "$dir/overlay.qcow2" 12G >/dev/null

  if [ "$(uname -m)" = "x86_64" ] && [ -w /dev/kvm ]; then ACCEL=kvm CPU=host; else ACCEL=tcg CPU=max; fi
  export ACCEL CPU DIR="$dir"
  echo "== [$d] boot (accel=$ACCEL) ==" >&2
  # shellcheck disable=SC2016
  nix shell "$NIXPKGS#qemu" "$NIXPKGS#swtpm" "$NIXPKGS#coreutils" -c bash -c '
		swtpm socket --tpm2 --tpmstate dir="$DIR/tpm" \
			--ctrl type=unixio,path="$DIR/swtpm-sock" --flags startup-clear &
		SW=$!; trap "kill $SW 2>/dev/null || true" EXIT; sleep 1
		timeout 2400 qemu-system-x86_64 \
			-machine q35 -accel "$ACCEL" -cpu "$CPU" -smp 2 -m 2048 -nographic \
			-drive file="$DIR/overlay.qcow2",if=virtio,format=qcow2 \
			-drive file="$DIR/seed.img",if=virtio,format=raw \
			-netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
			-chardev socket,id=chrtpm,path="$DIR/swtpm-sock" \
			-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-crb,tpmdev=tpm0 \
			-serial mon:stdio -display none
	' 2>&1 | tee "$dir/boot.log" | grep -aE "RESULT |SINETE_VM_|DRIVER (DONE|kernel)|--- \[" || true

  # Preserve the full serial log past WORK cleanup (for inspecting failures).
  mkdir -p "$CACHE/logs"
  cp "$dir/boot.log" "$CACHE/logs/$d-boot.log" 2>/dev/null || true

  if grep -aq "SINETE_VM_PASS" "$dir/boot.log"; then
    echo "PASS: $d"
    return 0
  fi
  echo "FAIL: $d — last 30 guest lines:" >&2
  sed 's/\x1b\[[0-9;]*m//g' "$dir/boot.log" | grep -avE '^\[' | tail -30 >&2
  return 1
}

rc=0
for d in $DISTROS; do run_distro "$d" || rc=1; done
echo "== matrix verdict: $([ $rc -eq 0 ] && echo ALL PASS || echo FAIL) =="
exit $rc
