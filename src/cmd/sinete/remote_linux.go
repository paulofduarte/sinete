// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/paulofduarte/sinete/internal/localsession"
	"golang.org/x/sys/unix"
)

// presenceUnavailable reports whether conn's peer cannot answer a *local* presence
// prompt, so the agent should refuse to sign its cryptoprocessor keys for it (List
// and upstream keys still work). See the contract in remote.go.
//
// Unlike the macOS detector — which fails OPEN (uncertainty ⇒ treat as local)
// because Touch ID is console-only by construction — the Linux detector fails
// CLOSED: it refuses unless it can POSITIVELY confirm the peer's session is local.
// On Linux pinentry will happily prompt on an SSH pty, so a remote user who knows
// the PIN could answer it; treating an unconfirmed session as local would let a
// remote session sign. So here the remote check is the security boundary, and it
// must be unspoofable.
//
// "Local" is the peer's logind/elogind session Remote property being false
// (org.freedesktop.login1), resolved from its SO_PEERCRED pid — a value the system
// sets at login from the session class, which the client can't forge via its
// environment. The unspoofable lookup lives in internal/localsession, shared with
// config signing. If logind/elogind is unavailable, presence is refused and a
// one-time diagnostic is logged.
//
// TODO(presence-gap): close the no-logind gap on seatd-based systems (e.g. Chimera
// Linux, minimal Wayland setups) by also accepting a seatd seat session as
// positive-local — a seatd session is only ever local. ConsoleKit2 / turnstile are
// other candidates. See .claude/LINUX-PRESENCE.md.
func presenceUnavailable(conn net.Conn) bool {
	pid, uid, ok := peerCreds(conn)
	if !ok {
		return true // can't read peer credentials ⇒ can't confirm local ⇒ refuse
	}
	local, err := localsession.IsLocal(pid, uid)
	if err != nil {
		if localsession.Unavailable(err) {
			warnNoLogind()
		}
		return true // can't confirm a local session ⇒ refuse (fail closed)
	}
	return !local
}

// peerCreds returns the connecting peer's pid and uid via SO_PEERCRED. ok is false when
// conn is not a unix socket, the credentials can't be read, or the pid is not positive
// (a guard against a 0/-1 pid being widened to a bogus uint32 and matched to an
// unrelated session). The uid is used to confirm local presence when the peer is not in
// a session scope (see localsession.IsLocal).
func peerCreds(conn net.Conn) (pid, uid uint32, ok bool) {
	uc, isUnix := conn.(*net.UnixConn)
	if !isUnix {
		return 0, 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil || cred.Pid <= 0 {
		return 0, 0, false
	}
	return uint32(cred.Pid), cred.Uid, true
}

// noLogindOnce keeps the missing-logind diagnostic to a single line: it's an
// environment condition, not a per-connection event, so logging it once is enough
// to tell the operator why presence is being refused.
var noLogindOnce sync.Once

func warnNoLogind() {
	noLogindOnce.Do(func() {
		fmt.Fprintln(os.Stderr, "sinete: cannot confirm a local session via logind/elogind — it is not installed/running, or the system bus is unavailable or unresponsive. Refusing presence-gated signatures until local presence can be detected (remote sessions are always refused).")
	})
}
