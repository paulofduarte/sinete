// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"net"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// presenceUnavailable reports whether conn's peer is a remote (e.g. SSH) login
// session, which cannot answer a local user-presence prompt — so the agent refuses
// to sign its cryptoprocessor keys for it rather than block on a pinentry/fprintd
// prompt the remote user can never reach. See the contract in remote.go.
//
// Unlike macOS, a local *text console* is fine here: pinentry can prompt on a tty,
// so only sessions logind marks as remote are refused. The signal is the peer's
// logind session Remote property, resolved from its SO_PEERCRED pid — set by the
// system at login, so it can't be spoofed via the client's environment the way an
// SSH_CONNECTION scan can.
//
// Conservative: any failure to read the peer's session (not a unix socket, the
// syscall fails, no logind session, D-Bus unavailable) is treated as local, so we
// never wrongly block a legitimate local user.
func presenceUnavailable(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}

	var (
		ucred   *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil || ucred == nil {
		return false
	}

	return sessionIsRemote(uint32(ucred.Pid))
}

// sessionIsRemote reports whether the logind session owning pid is a remote login.
// It returns false on any error (no session, logind/D-Bus unavailable), per the
// conservative-local contract in remote.go.
func sessionIsRemote(pid uint32) bool {
	const (
		dest    = "org.freedesktop.login1"
		mgrPath = "/org/freedesktop/login1"
		mgrIf   = "org.freedesktop.login1.Manager"
		sessIf  = "org.freedesktop.login1.Session"
	)

	bus, err := dbus.SystemBus()
	if err != nil {
		return false
	}

	var session dbus.ObjectPath
	if err := bus.Object(dest, mgrPath).
		Call(mgrIf+".GetSessionByPID", 0, pid).Store(&session); err != nil {
		return false
	}

	v, err := bus.Object(dest, session).GetProperty(sessIf + ".Remote")
	if err != nil {
		return false
	}
	remote, ok := v.Value().(bool)
	return ok && remote
}
