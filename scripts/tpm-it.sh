#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# Linux TPM integration test against swtpm, in an OrbStack/Docker Linux container (there is no TPM on
# a dev Mac, and CI can't run it). Cross-compiles the agent, then runs the selftest + a full
# generate -> list -> agent ssh-add -l -> ssh-keygen -Y sign -> verify -> remove round-trip. The
# pure marshaling is unit-tested separately by `zig build test`; this exercises the device path.
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
  mkdir -p /tmp/tpm /root; export HOME=/root
  swtpm socket --tpm2 --tpmstate dir=/tmp/tpm \
    --ctrl type=unixio,path=/tmp/tpm/ctrl --server type=unixio,path=/tmp/tpm/sock --flags startup-clear &
  sleep 2
  export SINETE_TPM=/tmp/tpm/sock
  B=/host/sinete

  "$B" _tpm-selftest | grep -q "SELFTEST PASS"
  echo "ok: selftest"

  "$B" generate ztest >/dev/null
  "$B" list | grep -q "ztest (ECDSA)"
  echo "ok: generate + list"

  "$B" agent --sock /tmp/a.sock >/tmp/a.log 2>&1 &
  sleep 1
  SSH_AUTH_SOCK=/tmp/a.sock ssh-add -l | grep -q "ztest (ECDSA)"
  echo "ok: agent ssh-add -l"

  SSH_AUTH_SOCK=/tmp/a.sock ssh-add -L > /tmp/k.pub
  printf "hello sinete z4" > /tmp/msg
  SSH_AUTH_SOCK=/tmp/a.sock ssh-keygen -Y sign -f /tmp/k.pub -n test /tmp/msg < /tmp/msg >/dev/null 2>&1
  echo "ztest@tpm $(cat /tmp/k.pub)" > /tmp/allowed
  ssh-keygen -Y verify -f /tmp/allowed -I ztest@tpm -n test -s /tmp/msg.sig < /tmp/msg | grep -q "Good"
  echo "ok: ssh-keygen -Y sign through the agent verifies"

  # the optional "sinete-" prefix resolves to the bare key name (parity with macOS)
  "$B" export sinete-ztest | grep -q "ztest"
  echo "ok: export resolves the optional sinete- prefix"

  "$B" remove ztest
  echo "ALL OK"
'
