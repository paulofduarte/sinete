// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paulofduarte/sinete/internal/registry"
)

func TestSshSetup(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)

	const pub = "ecdsa-sha2-nistp256 AAAATESTKEYBLOB work"
	r, err := registry.Open(filepath.Join(cfg, "sinete", "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	r.Add(registry.Entry{Name: "work", Label: "sinete-work", Tag: "me.paulofduarte.sinete", PublicKey: pub})
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "work.pub")
	if err := cmdSshSetup([]string{"--out", out, "work"}); err != nil {
		t.Fatalf("cmdSshSetup: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("public key not written: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != pub {
		t.Errorf("wrote %q, want %q", got, pub)
	}

	if err := cmdSshSetup([]string{"--out", out, "missing"}); err == nil {
		t.Error("ssh-setup on an unknown key should error")
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
