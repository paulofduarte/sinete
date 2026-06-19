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
//   - linux (remote_linux.go): the peer's logind/elogind session is NOT confirmed
//     local — i.e. its Session Remote property (resolved from the SO_PEERCRED pid)
//     is true, or no local session can be confirmed at all. A local text console is
//     fine (pinentry can prompt on a tty), so a confirmed-local session — graphical
//     or console — is allowed; only remote (or unconfirmable) ones are refused.
//   - other (remote_other.go): always false until a platform implements it.
//
// Fail direction differs by platform, and deliberately so:
//   - macOS fails OPEN (uncertainty ⇒ treat as local). Touch ID is console-only by
//     construction, so even a misclassified remote peer can't satisfy presence — the
//     worst case of a false negative is a prompt that may not show, not a bypass.
//   - Linux fails CLOSED (uncertainty ⇒ refuse). pinentry will prompt on an SSH pty,
//     so an unconfirmed session could be a remote one that answers it; the remote
//     check is therefore the security boundary and must be positively confirmed. The
//     cost is that a host without logind/elogind refuses presence-gated signing (with
//     a one-time diagnostic) until one is installed.

// presenceDenyingAgent is the agent capability the refusal flow needs: the full
// ExtendedAgent, plus sign variants that refuse a presence-gated cryptoprocessor key
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
// *DenyingPresence variants — which refuse sinete's own cryptoprocessor keys (those would
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
