#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# D-Bus integration test for the pure-Zig client (lib/dbus + src/backend/dbus_conn): connect to a
# real dbus-daemon, run the SASL EXTERNAL handshake, Hello, and validate the reply. This exercises
# the marshaling/alignment that unit tests can only check for internal consistency -- a real daemon
# rejects a wrong byte. There is no D-Bus on a dev Mac, so it runs in an OrbStack/Docker container.
# The fprintd/logind flows on top need their own daemons (a virtual fingerprint device / logind) and
# are covered by the manual checklist, not here.
#
# Usage:  scripts/dbus-it.sh        (needs docker/orbstack)

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

docker run --rm --security-opt seccomp=unconfined -v "$repo/zig-out/bin:/host:ro" alpine:latest sh -c '
  set -e
  apk add --no-cache dbus >/dev/null 2>&1
  dbus-uuidgen --ensure
  mkdir -p /run/dbus
  dbus-daemon --system --fork
  sleep 1
  /host/sinete _dbus-selftest | grep -q "DBUS SELFTEST PASS"
  echo "ok: SASL EXTERNAL + Hello round-trip against a real dbus-daemon"
  echo "ALL OK"
'
