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
