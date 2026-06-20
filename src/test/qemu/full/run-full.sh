#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Distro e2e MATRIX — the Linux TPM + local-session end-to-end test. Boots real cloud images
# — Debian (glibc / systemd-logind) and Alpine (musl / elogind) — under QEMU + swtpm and
# runs the full local-session + TPM matrix (src/test/qemu/full/driver.sh) on each:
# fail-closed refusal, remote(ssh)-refused on create & sign, _enclave-check TPM crypto,
# pinentry-curses/-tty/x-term signs, wrong-PIN rejection.
#
# NOT a per-build CI gate — it needs network (apt/apk) and is slow. Run on demand
# (`nix run .#e2e-linux-full`) or on releases. Needs `go`, `nix`, ~2 GB disk and net.
#
# Override the set with: DISTROS="debian" bash run-full.sh

set -euo pipefail

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
  # No root password is set: the guest is driven entirely by a serial autologin getty
  # (no auth) and key-based ssh, so there is nothing to brute-force even if a port were
  # ever forwarded. The distro shims also leave ssh password auth off.
  cat <<-'UD'
		#cloud-config
		runcmd:
		  - [ sh, -c, "mkdir -p /mnt/seed; m=0; for d in /dev/vdb /dev/vdb1 /dev/sr0 /dev/sdb /dev/sdb1; do mount -o ro $d /mnt/seed 2>/dev/null && [ -f /mnt/seed/driver.sh ] && { m=1; break; }; umount /mnt/seed 2>/dev/null; done; [ $m = 1 ] || { echo 'SEED MOUNT FAILED' > /dev/console; echo SINETE_VM_FAIL > /dev/console; poweroff -f; }; cp /mnt/seed/driver.sh /mnt/seed/distro.sh /mnt/seed/sinete /mnt/seed/fake-pinentry /root/ && chmod +x /root/driver.sh /root/sinete /root/fake-pinentry || { echo 'SEED COPY FAILED' > /dev/console; echo SINETE_VM_FAIL > /dev/console; poweroff -f; }; . /root/distro.sh; distro_provision > /dev/console 2>&1 || { echo 'PROVISION FAILED' > /dev/console; echo SINETE_VM_FAIL > /dev/console; poweroff -f; }" ]
	UD
}

# sha256_of prints "<hex>  <file>" — sha256sum on Linux / under nix, shasum -a 256 on a
# macOS direct run (no coreutils). Keeps `bash run-full.sh` working on both.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}

fetch_image() { # $1 distro  -> echoes cached image path
  local d="$1" url sha img
  # Upstream cloud images, version-pinned with a verified sha256 (cached after first
  # fetch). To bump: change the URL, download it, verify its sha against upstream's
  # published checksum, and paste the new sha256 here. Debian prunes dated snapshots
  # eventually — when this 404s, bump to a current snapshot. (Debian's sha256 below was
  # cross-checked against the snapshot's official SHA512SUMS.)
  case "$d" in
  debian)
    url="https://cloud.debian.org/images/cloud/bookworm/20251112-2294/debian-12-genericcloud-amd64-20251112-2294.qcow2"
    sha="510f0bc0814fe298ec944c5bf97598699b2dec033fa79c6802cc3af8948217de"
    ;;
  alpine)
    url="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/cloud/nocloud_alpine-3.21.2-x86_64-bios-cloudinit-r0.qcow2"
    sha="671d5264be976b391e5c69162a1fd87ed77f992eaa70c4ee5b53953a540c663d"
    ;;
  *)
    echo "FATAL: unknown distro $d" >&2
    exit 1
    ;;
  esac
  img="$CACHE/$(basename "$url")"
  if [ ! -f "$img" ]; then
    echo "== fetch $d image ($(basename "$url")) ==" >&2
    # Retry to ride out transient CDN/network hiccups on CI/release runners.
    curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors -o "$img.part" "$url" || {
      echo "FATAL: $d image download failed ($url)" >&2
      rm -f "$img.part"
      return 1
    }
    mv "$img.part" "$img"
  fi
  # Integrity is mandatory: the image is booted under QEMU (incl. on the release runner),
  # so a silently-changed/compromised image must not run. Re-pin intentionally on a bump.
  [ -n "$sha" ] || {
    echo "FATAL: $d image sha256 not pinned" >&2
    return 1
  }
  got="$(sha256_of "$img")"
  got="${got%% *}" # strip the trailing "  <file>", leaving just the hash
  [ "$got" = "$sha" ] || {
    echo "FATAL: $d image sha256 mismatch (upstream changed?) — re-pin, or remove $img and retry" >&2
    return 1
  }
  echo "$img"
}

run_distro() { # $1 distro -> 0 pass / 1 fail
  # Called as `run_distro || rc=1`, so per bash `set -e` is ignored throughout this
  # function body — unguarded failures here do NOT abort. Hence the explicit `|| return
  # 1` on each setup step, so a failure is reported as a FAIL rather than booting with
  # bad inputs.
  local d="$1" img dir
  img="$(fetch_image "$d")" || return 1
  dir="$WORK/$d"
  mkdir -p "$dir/seed" "$dir/tpm"
  printf 'instance-id: sinete-%s\nlocal-hostname: sinete-%s\n' "$d" "$d" >"$dir/seed/meta-data"
  emit_user_data >"$dir/seed/user-data"
  cp "$HERE/driver.sh" "$dir/seed/driver.sh"
  cp "$HERE/distro-$d.sh" "$dir/seed/distro.sh"
  cp "$HERE/../fake-pinentry.sh" "$dir/seed/fake-pinentry"
  cp "$WORK/sinete" "$dir/seed/sinete"

  echo "== [$d] build vfat cidata seed + overlay ==" >&2
  # bash -ec: any step (truncate/mformat/mcopy) failing propagates, so `|| return 1`
  # catches it, not only the last command. ($dir is spliced in host-side via the quotes.)
  nix shell "$NIXPKGS#mtools" "$NIXPKGS#coreutils" -c bash -ec '
		truncate -s 96M "'"$dir"'/seed.img"
		mformat -i "'"$dir"'/seed.img" -v cidata -T 196608 ::
		mcopy -i "'"$dir"'/seed.img" "'"$dir"'/seed/"* ::' >&2 || return 1
  nix shell "$NIXPKGS#qemu" -c qemu-img create -f qcow2 -F qcow2 -b "$img" "$dir/overlay.qcow2" 12G >/dev/null || return 1

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
