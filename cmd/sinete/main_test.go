// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
