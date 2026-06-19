// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package localsession answers one question on Linux: is a given process's login
// session LOCAL (at the machine), as opposed to remote (SSH) or unconfirmable? It
// resolves the session via logind/elogind (org.freedesktop.login1) by PID and reads
// its Remote property — a value the system sets at login from the session class,
// which a client cannot forge via its environment. It is the shared, unspoofable
// local-presence signal used both by the agent (to refuse signing cryptoprocessor
// keys for a remote peer) and by config signing (to refuse a remote master-key PIN
// prompt).
//
// Every caller fails CLOSED: any error from IsLocalPID means "could not confirm
// local", and presence / PIN entry must then be refused. This is deliberate — on
// Linux pinentry will happily prompt on an SSH pty, so an unconfirmed session could
// be a remote one that answers it; the remote check is the security boundary and must
// be positively confirmed, never assumed.
package localsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

// dbusTimeout bounds the logind lookups so a slow or hung system bus can't stall the
// caller. On timeout the lookup errors and the caller fails closed (refuse), like any
// other failure to confirm a local session.
const dbusTimeout = 2 * time.Second

// IsLocalPID reports whether the logind/elogind session owning pid is local (its
// Remote property is false). It returns an error when localness cannot be confirmed —
// logind/elogind unavailable, the system bus is hung (timeout), or pid has no session
// — and every caller fails closed on any such error.
func IsLocalPID(pid uint32) (bool, error) {
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

// Unavailable reports whether err means local presence could not be detected because
// logind/elogind — or the system bus itself — was unreachable: a missing or stopped
// login1 service, no D-Bus at all, or a hung bus (timeout). It returns false for the
// routine case of logind being present but the pid simply having no session, which is
// a normal refusal, not a misconfiguration. It only gates an operator diagnostic, not
// the refusal itself (callers always fail closed).
func Unavailable(err error) bool {
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
