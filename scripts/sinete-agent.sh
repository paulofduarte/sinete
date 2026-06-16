#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Paulo Duarte
# SPDX-License-Identifier: Apache-2.0
#
# launchd wrapper for the sinete agent. It captures the session's existing agent
# as the upstream (so sinete delegates non-enclave keys to it), republishes
# SSH_AUTH_SOCK to point at sinete, then execs the agent.  Args: <bin> <socket>.
set -euo pipefail

bin="$1"
sock="$2"

# Wait briefly for the system ssh-agent to publish SSH_AUTH_SOCK at login (so we
# run "late" enough to capture it), then record it as the upstream -- but never
# our own socket, which would make sinete its own upstream across KeepAlive
# restarts.
for ((i = 0; i < 50; i++)); do
  up="$(launchctl getenv SSH_AUTH_SOCK || true)"
  if [ -n "$up" ] && [ "$up" != "$sock" ]; then
    launchctl setenv SINETE_UPSTREAM_SOCK "$up"
    break
  fi
  sleep 0.2
done

# Take over the session socket so ssh/git transparently use sinete.
launchctl setenv SSH_AUTH_SOCK "$sock"

SINETE_UPSTREAM_SOCK="$(launchctl getenv SINETE_UPSTREAM_SOCK || true)"
export SINETE_UPSTREAM_SOCK
exec "$bin" agent --socket "$sock"
