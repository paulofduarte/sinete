// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

// This file holds the OS-agnostic refusal flow. The only per-OS piece is the
// detector:
//
//	func presenceUnavailable(conn net.Conn) bool
//
// implemented in remote_<os>.go. It reports whether the peer of conn is a session
// that cannot answer a local user-presence prompt — so gating a signature on
// presence there would block on a prompt the user can never satisfy, and hang.
// Each platform computes this from its best local signal, and the predicate is
// deliberately platform-specific:
//
//   - darwin (remote_darwin.go): the peer's login session lacks window-server
//     access (it is remote/SSH, or otherwise headless), so the LocalAuthentication
//     Touch ID sheet cannot be drawn. Signal: SessionGetInfo on the peer's audit
//     session id (see .claude/REMOTE-DETECTION.md).
//   - linux (future): the peer's logind session is remote (sd_session_is_remote).
//     A local text console is NOT unavailable there — pinentry can prompt on a tty,
//     so only genuinely remote sessions are refused.
//   - other (remote_other.go): always false until a platform implements it.
//
// Detectors are conservative: on any uncertainty they return false (treat the peer
// as local), so we never wrongly block a legitimate local user — the cost of a
// false negative is at worst today's behaviour (a prompt that may not show), not a
// lockout.

// errRemotePresence is returned to a peer that can't satisfy a presence prompt when
// it tries to sign with one of sinete's enclave keys.
var errRemotePresence = errors.New("sinete: can't confirm user presence for this connection — it has no local interactive session (e.g. SSH); sign from the machine's console")

// remoteRefusingAgent wraps the agent for a connection whose peer can't satisfy a
// presence prompt (presenceUnavailable). It refuses signatures for sinete's own
// enclave keys — which would otherwise block on a prompt the peer can't see — while
// delegating everything else (List, and signing upstream-delegated keys) unchanged.
// owns reports whether a key is one sinete gates with presence (Agent.OwnsKey).
type remoteRefusingAgent struct {
	xagent.ExtendedAgent
	owns func(ssh.PublicKey) bool
}

func (r remoteRefusingAgent) refuse(key ssh.PublicKey) bool {
	if r.owns(key) {
		fmt.Fprintf(os.Stderr, "sinete agent: refused signing %s for a session that can't confirm presence (sign at the console)\n", ssh.FingerprintSHA256(key))
		return true
	}
	return false
}

func (r remoteRefusingAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if r.refuse(key) {
		return nil, errRemotePresence
	}
	return r.ExtendedAgent.Sign(key, data)
}

func (r remoteRefusingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags xagent.SignatureFlags) (*ssh.Signature, error) {
	if r.refuse(key) {
		return nil, errRemotePresence
	}
	return r.ExtendedAgent.SignWithFlags(key, data, flags)
}
