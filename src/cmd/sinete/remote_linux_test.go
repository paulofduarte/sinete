// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// notUnixConn is a net.Conn that is not a *net.UnixConn, to exercise peerCreds's
// non-unix-socket path.
type notUnixConn struct{ net.Conn }

func TestPeerCredsRejectsNonUnix(t *testing.T) {
	if _, _, ok := peerCreds(notUnixConn{}); ok {
		t.Error("peerCreds on a non-unix-socket conn must return ok=false (unconfirmable)")
	}
}

func TestPeerCredsUnixSocket(t *testing.T) {
	// A socketpair's peer is this same process, so SO_PEERCRED must report our pid + uid.
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

	pid, uid, ok := peerCreds(conn)
	if !ok {
		t.Fatal("peerCreds on a unix socketpair returned ok=false")
	}
	if pid != uint32(os.Getpid()) {
		t.Errorf("peerCreds pid = %d, want our pid %d", pid, os.Getpid())
	}
	if uid != uint32(os.Getuid()) {
		t.Errorf("peerCreds uid = %d, want our uid %d", uid, os.Getuid())
	}
}
