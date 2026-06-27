#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Linux TPM integration test against swtpm, in an OrbStack/Docker Linux container (there is no TPM on
# a dev Mac, and CI can't run it). Cross-compiles the agent, then exercises the device path: the Z4
# empty-auth crypto + key lifecycle, and the Z5b policy binding (a policy-bound key signs only via a
# policy session that proves the master secret; an empty-auth sign on it must fail). Two fresh swtpm
# instances are used so the policy selftest's master does not collide with the auto-enrolled one.
#
# The agent-mediated `ssh-keygen -Y sign` path is NOT exercised here: since Z5a it requires a
# fingerprint (fprintd) which a bare container has no way to provide -- that is a manual / virtual-
# device checklist item (manual/z5-linux-presence.md). Listing identities needs no presence, so the
# agent `ssh-add -l` is still checked. The pure marshaling is unit-tested by `zig build test`.
#
# Usage:  scripts/tpm-it.sh        (needs docker/orbstack)

set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

case "$(uname -m)" in
arm64 | aarch64) arch=aarch64 ;;
x86_64 | amd64) arch=x86_64 ;;
*)
    echo "unsupported host arch: $(uname -m)" >&2
    exit 1
    ;;
esac

echo "--- building the agent for ${arch}-linux-musl ---"
zig build -Doptimize=ReleaseFast "-Dtarget=${arch}-linux-musl"

# --security-opt seccomp=unconfined: the agent's libxev uses io_uring, which Docker's default seccomp
# profile blocks. A real Linux host has io_uring; this only relaxes the container for the test.
docker run --rm --security-opt seccomp=unconfined -v "$repo/zig-out/bin:/host:ro" alpine:latest sh -c '
  set -e
  apk add --no-cache swtpm openssh-client >/dev/null 2>&1
  mkdir -p /tmp/t1 /tmp/t2 /root; export HOME=/root
  for d in t1 t2; do
    swtpm socket --tpm2 --tpmstate dir=/tmp/$d \
      --ctrl type=unixio,path=/tmp/$d/ctrl --server type=unixio,path=/tmp/$d/sock --flags startup-clear &
  done
  sleep 2
  B=/host/sinete

  # Z5b policy binding, on its own fresh TPM (defines its own master).
  SINETE_TPM=/tmp/t1/sock "$B" _tpm-policy-selftest | grep -q "POLICY SELFTEST PASS"
  echo "ok: policy binding (empty-auth sign rejected, policy-session sign verifies)"

  # Z4 crypto + the key lifecycle, on a second fresh TPM.
  export SINETE_TPM=/tmp/t2/sock
  "$B" _tpm-selftest | grep -q "SELFTEST PASS"
  echo "ok: selftest"

  "$B" generate ztest >/dev/null
  "$B" list | grep -q "ztest (ECDSA)"
  echo "ok: generate + list (policy-bound key, master auto-enrolled)"

  # owner-only: directory 0700, key file and master secret 0600
  test "$(stat -c %a /root/.local/share/sinete/keys)" = 700
  test "$(stat -c %a /root/.local/share/sinete/keys/ztest)" = 600
  test "$(stat -c %a /root/.local/share/sinete/keys/master.secret)" = 600
  echo "ok: key dir 0700; key file + master.secret 0600"

  # generate must never clobber an existing key (exclusive create)
  if "$B" generate ztest >/dev/null 2>&1; then echo "FAIL: regenerate overwrote a key" >&2; exit 1; fi
  echo "ok: generate refuses to overwrite an existing key"

  "$B" agent --sock /tmp/a.sock >/tmp/a.log 2>&1 &
  sleep 1
  SSH_AUTH_SOCK=/tmp/a.sock ssh-add -l | grep -q "ztest (ECDSA)"
  echo "ok: agent ssh-add -l"

  # the optional "sinete-" prefix resolves to the bare key name (parity with macOS)
  "$B" export sinete-ztest | grep -q "ztest"
  echo "ok: export resolves the optional sinete- prefix"

  "$B" remove ztest
  echo "ALL OK"
'
