// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localsession

import (
	"context"
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// godbus returns *dbus.Error (pointer) for failed method calls — the type the
		// production code must match.
		{"service unknown (ptr)", &dbus.Error{Name: "org.freedesktop.DBus.Error.ServiceUnknown"}, true},
		{"name has no owner (ptr)", &dbus.Error{Name: "org.freedesktop.DBus.Error.NameHasNoOwner"}, true},
		{"no session for pid (ptr)", &dbus.Error{Name: "org.freedesktop.login1.NoSessionForPID"}, false},
		{"other login1 error (ptr)", &dbus.Error{Name: "org.freedesktop.login1.SomethingElse"}, false},
		// Value form is handled defensively.
		{"dbus.Error value", dbus.Error{Name: "org.freedesktop.login1.NoSessionForPID"}, false},
		{"context timeout", context.DeadlineExceeded, true},
		{"generic non-dbus", errors.New("bus connect failed"), true},
		// logind answered with an unexpected type: reachable, so NOT unavailable.
		{"malformed reply", errMalformedReply, false},
	}
	for _, c := range cases {
		if got := Unavailable(c.err); got != c.want {
			t.Errorf("%s: Unavailable = %v, want %v", c.name, got, c.want)
		}
	}
}

// isNoSessionForPID gates the fallback from the per-process check to the user's sessions
// (for GUI terminals / systemd --user processes that have no session of their own).
func TestIsNoSessionForPID(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"no session (ptr)", &dbus.Error{Name: "org.freedesktop.login1.NoSessionForPID"}, true},
		{"no session (value)", dbus.Error{Name: "org.freedesktop.login1.NoSessionForPID"}, true},
		{"other login1 error", &dbus.Error{Name: "org.freedesktop.login1.SomethingElse"}, false},
		{"service unknown", &dbus.Error{Name: "org.freedesktop.DBus.Error.ServiceUnknown"}, false},
		{"non-dbus error", errors.New("bus connect failed"), false},
	}
	for _, c := range cases {
		if got := isNoSessionForPID(c.err); got != c.want {
			t.Errorf("%s: isNoSessionForPID = %v, want %v", c.name, got, c.want)
		}
	}
}

// localOnlyForUID is the security decision for a session-less process: confirm the user
// is local-only (≥1 local session, none remote). These cases pin down the boundary —
// most importantly that a mixed local+remote user fails closed, and that another user's
// remote session is irrelevant.
func TestLocalOnlyForUID(t *testing.T) {
	const me, other = uint32(1000), uint32(1001)
	cases := []struct {
		name     string
		sessions []sessionRemoteInfo
		want     bool
	}{
		{"no sessions at all", nil, false},
		{"only another user's local session", []sessionRemoteInfo{{other, false}}, false},
		{"only another user's remote session", []sessionRemoteInfo{{other, true}}, false},
		{"one local session for me", []sessionRemoteInfo{{me, false}}, true},
		{"one remote session for me", []sessionRemoteInfo{{me, true}}, false},
		{"mixed local+remote for me ⇒ refuse", []sessionRemoteInfo{{me, false}, {me, true}}, false},
		{"remote-then-local for me ⇒ refuse (order-independent)", []sessionRemoteInfo{{me, true}, {me, false}}, false},
		{"two local sessions for me", []sessionRemoteInfo{{me, false}, {me, false}}, true},
		{"my local + another user's remote ⇒ allow", []sessionRemoteInfo{{me, false}, {other, true}}, true},
	}
	for _, c := range cases {
		if got := localOnlyForUID(c.sessions, me); got != c.want {
			t.Errorf("%s: localOnlyForUID = %v, want %v", c.name, got, c.want)
		}
	}
}
