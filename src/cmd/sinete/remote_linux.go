// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// dbusTimeout bounds the logind lookups so a slow or hung system bus can't stall
// accepting a new agent connection. On timeout we fail closed (refuse), like any
// other failure to confirm a local session.
const dbusTimeout = 2 * time.Second

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
// environment. If logind/elogind is unavailable, presence is refused and a one-time
// diagnostic is logged: sinete needs systemd-logind or elogind for local-presence
// detection.
//
// TODO(presence-gap): close the no-logind gap on seatd-based systems (e.g. Chimera
// Linux, minimal Wayland setups) by also accepting a seatd seat session as
// positive-local — a seatd session is only ever local. ConsoleKit2 / turnstile are
// other candidates. See .claude/LINUX-PRESENCE.md.
func presenceUnavailable(conn net.Conn) bool {
	pid, ok := peerPID(conn)
	if !ok {
		return true // can't read peer credentials ⇒ can't confirm local ⇒ refuse
	}
	local, err := sessionIsLocal(pid)
	if err != nil {
		if logindUnavailable(err) {
			warnNoLogind()
		}
		return true // can't confirm a local session ⇒ refuse (fail closed)
	}
	return !local
}

// peerPID returns the connecting peer's pid via SO_PEERCRED. ok is false when conn
// is not a unix socket, the credentials can't be read, or the pid is not positive
// (a guard against a 0/-1 pid being widened to a bogus uint32 and matched to an
// unrelated session).
func peerPID(conn net.Conn) (uint32, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil || cred.Pid <= 0 {
		return 0, false
	}
	return uint32(cred.Pid), true
}

// sessionIsLocal reports whether the logind/elogind session owning pid is local (its
// Remote property is false). It returns an error when localness cannot be confirmed
// — logind/elogind unavailable, the system bus is hung (timeout), or pid has no
// session — and the caller fails closed on any such error.
func sessionIsLocal(pid uint32) (bool, error) {
	const (
		dest     = "org.freedesktop.login1"
		mgrPath  = "/org/freedesktop/login1"
		mgrIf    = "org.freedesktop.login1.Manager"
		sessIf   = "org.freedesktop.login1.Session"
		propsGet = "org.freedesktop.DBus.Properties.Get"
	)

	bus, err := dbus.SystemBus()
	if err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), dbusTimeout)
	defer cancel()

	var session dbus.ObjectPath
	if err := bus.Object(dest, mgrPath).
		CallWithContext(ctx, mgrIf+".GetSessionByPID", 0, pid).Store(&session); err != nil {
		return false, err
	}

	var remote dbus.Variant
	if err := bus.Object(dest, session).
		CallWithContext(ctx, propsGet, 0, sessIf, "Remote").Store(&remote); err != nil {
		return false, err
	}
	r, ok := remote.Value().(bool)
	if !ok {
		return false, fmt.Errorf("login1 Session.Remote is not a bool")
	}
	return !r, nil
}

// logindUnavailable reports whether err means local presence could not be detected
// because logind/elogind — or the system bus itself — was unreachable: a missing or
// stopped login1 service, no D-Bus at all, or a hung bus (timeout). It returns false
// for the routine case of logind being present but the peer simply having no session,
// which is a normal refusal, not a misconfiguration. It only gates the one-time
// operator diagnostic, not the refusal itself (the caller always fails closed).
func logindUnavailable(err error) bool {
	name, ok := dbusErrorName(err)
	if !ok {
		// Not a D-Bus method error: a SystemBus() connect failure (no D-Bus at all)
		// or a context timeout (bus hung) — either way presence can't be detected.
		return true
	}
	switch name {
	case "org.freedesktop.DBus.Error.ServiceUnknown",
		"org.freedesktop.DBus.Error.NameHasNoOwner":
		return true // org.freedesktop.login1 has no owner: no logind/elogind running
	default:
		return false // a login1 error (e.g. no session for pid): logind IS present
	}
}

// dbusErrorName extracts a D-Bus error name from err. godbus returns *dbus.Error for
// failed method calls; the value form is handled too, defensively.
func dbusErrorName(err error) (string, bool) {
	var ep *dbus.Error
	if errors.As(err, &ep) && ep != nil {
		return ep.Name, true
	}
	var ev dbus.Error
	if errors.As(err, &ev) {
		return ev.Name, true
	}
	return "", false
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
