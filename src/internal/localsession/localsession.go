// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package localsession answers one question on Linux: is a process (and its user)
// operating LOCALLY (at the machine), as opposed to remotely (SSH) or unconfirmable? It
// resolves this via logind/elogind (org.freedesktop.login1): a session's Remote property
// — set by the system at login from the session class, which a client cannot forge via
// its environment — and, for processes that run outside a session scope (graphical
// terminals, systemd --user services), the user's other sessions. It is the shared,
// unspoofable local-presence signal used both by the agent (to refuse signing
// cryptoprocessor keys for a remote peer) and by config signing (to refuse a remote
// master-key PIN prompt).
//
// Every caller fails CLOSED: any error from IsLocal means "could not confirm local", and
// presence / PIN entry must then be refused. This is deliberate — on Linux pinentry will
// happily prompt on an SSH pty, so an unconfirmed session could be a remote one that
// answers it; the remote check is the security boundary and must be positively
// confirmed, never assumed.
package localsession

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

// RequireLocalSelf refuses unless THIS process — or, when it isn't in a session scope,
// its user — is positively local. It is the own-process counterpart of the agent's peer
// check, on the same unspoofable signal, fail-closed. It is the Linux half of the
// cross-platform local-session gate (see the darwin and other-platform files).
func RequireLocalSelf() error {
	local, err := IsLocal(uint32(os.Getpid()), uint32(os.Getuid()))
	if err != nil {
		if Unavailable(err) {
			return fmt.Errorf("sinete needs systemd-logind or elogind to confirm this is a local session before a presence-gated operation — install/start one and run sinete at the machine (remote sessions are refused): %w", err)
		}
		return fmt.Errorf("cannot confirm a local session for a presence-gated operation; refusing: %w", err)
	}
	if !local {
		return errors.New("refusing a presence-gated operation: no local session for this user (a remote/SSH session, or no local login). Run sinete at the machine, where the master-key PIN is entered")
	}
	return nil
}

// dbusTimeout bounds the logind lookups so a slow or hung system bus can't stall the
// caller. On timeout the lookup errors and the caller fails closed (refuse), like any
// other failure to confirm a local session.
const dbusTimeout = 2 * time.Second

// errMalformedReply is returned when logind answers but its Session.Remote property
// is not the expected bool. logind IS reachable in this case, so Unavailable reports
// false for it (the caller still fails closed, but it is not a "no logind" condition).
var errMalformedReply = errors.New("login1 Session.Remote is not a bool")

const (
	loginDest    = "org.freedesktop.login1"
	loginMgrPath = "/org/freedesktop/login1"
	loginMgrIf   = "org.freedesktop.login1.Manager"
	loginSessIf  = "org.freedesktop.login1.Session"
	propsGet     = "org.freedesktop.DBus.Properties.Get"
)

// IsLocal reports whether pid — or, when pid is not in a session scope, its user uid —
// is operating LOCALLY (at the machine) rather than remotely (SSH).
//
//   - If pid is in a logind/elogind session, its Remote property is authoritative: a
//     console/graphical session is local, an SSH session is not. This is precise — if a
//     user is logged in both locally and over SSH, the SSH process is caught here.
//   - If pid is NOT in a session (GetSessionByPID returns NoSessionForPID), the process
//     escaped the login session cgroup. This is the common local case: graphical
//     terminals (gnome-terminal, konsole) run shells under user@.service, and so do
//     systemd --user / D-Bus-activated apps and lingering services. A real SSH process,
//     by contrast, is always inside its sshd session (caught above). So we fall back to
//     "does this user have any LOCAL (non-remote) session?" — true ⇒ the user is present
//     at the machine.
//
// It errors when localness can't be determined (no logind/elogind, hung bus, malformed
// reply); every caller fails closed on an error.
func IsLocal(pid, uid uint32) (bool, error) {
	bus, err := dbus.SystemBus()
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbusTimeout)
	defer cancel()

	session, err := sessionByPID(bus, ctx, pid)
	switch {
	case err == nil:
		remote, rerr := sessionRemote(bus, ctx, session)
		if rerr != nil {
			return false, rerr
		}
		return !remote, nil
	case isNoSessionForPID(err):
		return userHasLocalSession(bus, ctx, uid)
	default:
		return false, err
	}
}

func sessionByPID(bus *dbus.Conn, ctx context.Context, pid uint32) (dbus.ObjectPath, error) {
	var session dbus.ObjectPath
	err := bus.Object(loginDest, loginMgrPath).
		CallWithContext(ctx, loginMgrIf+".GetSessionByPID", 0, pid).Store(&session)
	return session, err
}

// sessionRemote reads a session's Remote property.
func sessionRemote(bus *dbus.Conn, ctx context.Context, session dbus.ObjectPath) (bool, error) {
	var remote dbus.Variant
	if err := bus.Object(loginDest, session).
		CallWithContext(ctx, propsGet, 0, loginSessIf, "Remote").Store(&remote); err != nil {
		return false, err
	}
	r, ok := remote.Value().(bool)
	if !ok {
		return false, errMalformedReply
	}
	return r, nil
}

// userHasLocalSession reports whether uid has any session whose Remote property is false
// (a local console/graphical login). A remote-only user (SSH sessions only) yields false.
func userHasLocalSession(bus *dbus.Conn, ctx context.Context, uid uint32) (bool, error) {
	var sessions []struct {
		ID   string
		UID  uint32
		User string
		Seat string
		Path dbus.ObjectPath
	}
	if err := bus.Object(loginDest, loginMgrPath).
		CallWithContext(ctx, loginMgrIf+".ListSessions", 0).Store(&sessions); err != nil {
		return false, err
	}
	for _, s := range sessions {
		if s.UID != uid {
			continue
		}
		remote, err := sessionRemote(bus, ctx, s.Path)
		if err != nil {
			continue // skip a session we can't read rather than fail the whole check
		}
		if !remote {
			return true, nil // a local session for this user ⇒ they are at the machine
		}
	}
	return false, nil
}

// isNoSessionForPID reports whether err is logind's "this pid has no session" — the
// signal to fall back to the user's sessions.
func isNoSessionForPID(err error) bool {
	name, ok := dbusErrorName(err)
	return ok && name == "org.freedesktop.login1.NoSessionForPID"
}

// Unavailable reports whether err means local presence could not be detected because
// logind/elogind — or the system bus itself — was unreachable: a missing or stopped
// login1 service, no D-Bus at all, or a hung bus (timeout). It returns false for the
// routine case of logind being present but the pid simply having no session, which is
// a normal refusal, not a misconfiguration. It only gates an operator diagnostic, not
// the refusal itself (callers always fail closed).
func Unavailable(err error) bool {
	if errors.Is(err, errMalformedReply) {
		// logind answered (it is reachable) but with an unexpected type — not a
		// "logind unavailable" condition, so don't emit the no-logind diagnostic.
		return false
	}
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
