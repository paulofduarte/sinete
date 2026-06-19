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
	}
	for _, c := range cases {
		if got := Unavailable(c.err); got != c.want {
			t.Errorf("%s: Unavailable = %v, want %v", c.name, got, c.want)
		}
	}
}
