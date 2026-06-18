// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Keys come from secure-element enumeration (which needs the entitled bundle), so
// the success path is exercised on-device via `sinete _enclave-check` and manual
// `ssh-setup`. Here we cover the error paths: an invalid name is rejected before
// any keychain access, and a valid name with no usable key — enumeration errors
// or finds no match for an unentitled test process — yields an error rather than
// writing a file.
func TestSshSetupErrors(t *testing.T) {
	out := filepath.Join(t.TempDir(), "k.pub")

	if err := cmdSshSetup([]string{"--out", out, "../evil"}); err == nil {
		t.Error("ssh-setup should reject an invalid key name")
	}
	if err := cmdSshSetup([]string{"--out", out, "work"}); err == nil {
		t.Error("ssh-setup on an unknown key should error")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("ssh-setup wrote %s for a key that does not exist", out)
	}
}

func TestSameSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A symlink to our socket must be recognised as the same file: a string
	// compare would miss it and the agent would delegate to itself.
	link := filepath.Join(dir, "agent-link.sock")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}

	if !sameSocket(sock, sock) {
		t.Error("identical paths should match")
	}
	if !sameSocket(sock, link) {
		t.Error("a symlink to the socket should match (self-delegation guard)")
	}

	other := filepath.Join(dir, "other.sock")
	ln2, err := net.Listen("unix", other)
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	if sameSocket(sock, other) {
		t.Error("distinct sockets should not match")
	}
	if sameSocket(sock, filepath.Join(dir, "nope.sock")) {
		t.Error("a nonexistent path should not match")
	}
}
