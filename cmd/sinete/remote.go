// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
//     session id.
//   - linux (future): the peer's logind session is remote (sd_session_is_remote).
//     A local text console is NOT unavailable there — pinentry can prompt on a tty,
//     so only genuinely remote sessions are refused.
//   - other (remote_other.go): always false until a platform implements it.
//
// Detectors are conservative: on any uncertainty they return false (treat the peer
// as local), so we never wrongly block a legitimate local user — the cost of a
// false negative is at worst today's behaviour (a prompt that may not show), not a
// lockout.

// presenceDenyingAgent is the agent capability the refusal flow needs: the full
// ExtendedAgent, plus sign variants that refuse a presence-gated enclave key
// (rather than prompt) while still delegating upstream keys. *agent.Agent provides
// these; the refusal decision is made there with a single authoritative ownership
// lookup, so this wrapper holds no ownership logic of its own.
type presenceDenyingAgent interface {
	xagent.ExtendedAgent
	SignDenyingPresence(key ssh.PublicKey, data []byte) (*ssh.Signature, error)
	SignWithFlagsDenyingPresence(key ssh.PublicKey, data []byte, flags xagent.SignatureFlags) (*ssh.Signature, error)
}

// remoteRefusingAgent wraps the agent for a connection whose peer can't satisfy a
// presence prompt (presenceUnavailable). It routes signing through the agent's
// *DenyingPresence variants — which refuse sinete's own enclave keys (those would
// otherwise block on a prompt the peer can't see) and delegate everything else
// unchanged — while the embedded interface serves List and the rest as normal.
type remoteRefusingAgent struct {
	presenceDenyingAgent
}

func (r remoteRefusingAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.SignDenyingPresence(key, data)
}

func (r remoteRefusingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags xagent.SignatureFlags) (*ssh.Signature, error) {
	return r.SignWithFlagsDenyingPresence(key, data, flags)
}
