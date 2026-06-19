// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// notUnixConn is a net.Conn that is not a *net.UnixConn, to exercise peerPID's
// non-unix-socket path.
type notUnixConn struct{ net.Conn }

func TestPeerPIDRejectsNonUnix(t *testing.T) {
	if _, ok := peerPID(notUnixConn{}); ok {
		t.Error("peerPID on a non-unix-socket conn must return ok=false (unconfirmable)")
	}
}

func TestPeerPIDUnixSocket(t *testing.T) {
	// A socketpair's peer is this same process, so SO_PEERCRED must report our pid.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	f := os.NewFile(uintptr(fds[0]), "sock")
	defer f.Close()
	_ = unix.Close(fds[1])

	conn, err := net.FileConn(f)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	defer conn.Close()

	pid, ok := peerPID(conn)
	if !ok {
		t.Fatal("peerPID on a unix socketpair returned ok=false")
	}
	if pid != uint32(os.Getpid()) {
		t.Errorf("peerPID = %d, want our pid %d", pid, os.Getpid())
	}
}

func TestLogindUnavailable(t *testing.T) {
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
		if got := logindUnavailable(c.err); got != c.want {
			t.Errorf("%s: logindUnavailable = %v, want %v", c.name, got, c.want)
		}
	}
}
