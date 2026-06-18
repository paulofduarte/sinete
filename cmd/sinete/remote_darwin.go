// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

/*
#cgo LDFLAGS: -lbsm -framework Security
#include <bsm/libbsm.h>
#include <Security/AuthSession.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdint.h>

// peer_session_attrs fetches the connecting peer's login-session attribute bits for
// a connected unix-socket fd, using only supported (non-deprecated) APIs:
//
//   getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)  -> the peer's audit token
//   audit_token_to_asid()                   -> the peer's session id
//   SessionGetInfo()                        -> that session's SessionAttributeBits
//
// The attribute bits (sessionHasGraphicAccess, sessionIsRemote, ...) are set by the
// system at session creation and are not derived from the client's environment, so
// they can't be spoofed the way an SSH_CONNECTION env scan can. Returns 0 on success
// with *attrs set; a non-zero errno/OSStatus otherwise. No privilege required.
static int peer_session_attrs(int fd, uint32_t *attrs) {
  audit_token_t tok;
  socklen_t len = sizeof(tok);
  if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &tok, &len) != 0) {
    return errno ? errno : -1;
  }
  if (len != sizeof(tok)) {
    return -2; // short token: don't derive an asid from a partial audit token
  }
  au_asid_t asid = audit_token_to_asid(tok);
  SessionAttributeBits bits = 0;
  OSStatus rc = SessionGetInfo((SecuritySessionId)asid, NULL, &bits);
  if (rc != 0) {
    return (int)rc;
  }
  *attrs = (uint32_t)bits;
  return 0;
}
*/
import "C"

import "net"

// SessionAttributeBits we care about (from <Security/AuthSession.h>).
const (
	sessionHasGraphicAccess = 0x0010 // the session can reach the window server (can draw a GUI)
	sessionIsRemote         = 0x1000 // the session was established over the network (SSH)
)

// presenceUnavailable reports whether conn's peer is a session that cannot display
// the macOS LocalAuthentication (Touch ID) prompt: a remote (SSH) login, or any
// session without window-server access. Such a peer can't satisfy presence, so the
// agent refuses to sign its enclave keys for it rather than hang on an invisible
// prompt. See the contract in remote.go and .claude/REMOTE-DETECTION.md.
//
// Conservative: any failure to read the peer's session (not a unix socket, the
// syscall fails, SessionGetInfo errors) is treated as local — we never wrongly block
// a legitimate local user.
func presenceUnavailable(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var attrs C.uint32_t
	rc := C.int(-1)
	if err := raw.Control(func(fd uintptr) {
		rc = C.peer_session_attrs(C.int(fd), &attrs)
	}); err != nil || rc != 0 {
		return false
	}
	a := uint32(attrs)
	// Refuse when the peer can't draw the prompt: a remote session, or one without
	// graphic access. (A remote session also lacks graphic access, but checking both
	// is explicit and cheap.)
	return a&sessionIsRemote != 0 || a&sessionHasGraphicAccess == 0
}
