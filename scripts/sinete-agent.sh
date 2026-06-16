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

# Record the session's existing agent as the upstream. The system ssh-agent
# publishes SSH_AUTH_SOCK at login, before this RunAtLoad agent, so one read is
# enough. We never capture our own socket: on a KeepAlive restart SSH_AUTH_SOCK
# is already ours, so we skip and keep the upstream captured on the first run.
# (To delegate to a fixed-socket agent instead, set SINETE_UPSTREAM_SOCK in the
# launchd environment and this is a no-op.)
up="$(launchctl getenv SSH_AUTH_SOCK || true)"
if [ -n "$up" ] && [ "$up" != "$sock" ]; then
  launchctl setenv SINETE_UPSTREAM_SOCK "$up"
fi

# Take over the session socket so ssh/git transparently use sinete.
launchctl setenv SSH_AUTH_SOCK "$sock"

SINETE_UPSTREAM_SOCK="$(launchctl getenv SINETE_UPSTREAM_SOCK || true)"
export SINETE_UPSTREAM_SOCK
exec "$bin" agent --socket "$sock"
