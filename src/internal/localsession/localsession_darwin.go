// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package localsession

/*
#cgo LDFLAGS: -framework Security
#include <Security/AuthSession.h>
#include <stdint.h>

// current_session_attrs fetches THIS process's login-session attribute bits via
// SessionGetInfo(callerSecuritySession) — the same supported API the agent uses on a
// peer's session (cmd/sinete/remote_darwin.go), but pointed at our own session. The
// bits are set by the system at session creation and can't be forged via the
// environment. Returns 0 with *attrs set on success, a non-zero OSStatus otherwise.
static int current_session_attrs(uint32_t *attrs) {
  SessionAttributeBits bits = 0;
  OSStatus rc = SessionGetInfo(callerSecuritySession, NULL, &bits);
  if (rc != 0) {
    return (int)rc;
  }
  *attrs = (uint32_t)bits;
  return 0;
}
*/
import "C"

import "errors"

// sessionIsRemote (from <Security/AuthSession.h>) marks a session established over the
// network (SSH). It is a system-set audit attribute, not derived from the environment,
// so it is the unspoofable macOS analogue of logind's Remote property.
const sessionIsRemote = 0x1000

// RequireLocalSelf is the macOS half of the cross-platform local-session gate: it
// refuses unless THIS process's session is local (not remote/SSH). It checks ONLY
// sessionIsRemote — the local/remote security boundary. It deliberately does NOT check
// sessionHasGraphicAccess: whether a GUI presence prompt can actually draw is the
// Secure Enclave / LocalAuthentication layer's concern (and on a headless-but-local
// session macOS may still present a passcode prompt), exactly as pinentry's
// drawability is separate from the Linux remote check. Conflating the two would wrongly
// block a legitimate local session that simply lacks the window server.
//
// Fail OPEN on a read error (unlike Linux's fail-closed): macOS user presence is
// presented locally by construction, so a misclassified session cannot yield a remote
// signature — the SE user-presence ACL backstops it. Linux fails closed only because
// pinentry can prompt on an SSH pty; macOS has no such hole.
func RequireLocalSelf() error {
	var attrs C.uint32_t
	if rc := C.current_session_attrs(&attrs); rc != 0 {
		return nil // can't read the session ⇒ fail open; the SE user-presence ACL still enforces locality
	}
	if uint32(attrs)&sessionIsRemote != 0 {
		return errors.New("refusing a presence-gated operation from a remote session — change sinete's presence config at the machine (macOS presents Touch ID / the passcode locally)")
	}
	return nil
}
