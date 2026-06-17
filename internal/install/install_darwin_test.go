// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package install

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCreateLinkUser covers the non-admin link path: it creates the symlink,
// is idempotent on replace, and removeLink deletes it (and tolerates absence).
func TestCreateLinkUser(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sinete-bin")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "bin", "sinete") // parent dir does not exist yet

	p := &Plan{Method: User, Target: target, LinkPath: link}
	if err := createLink(p); err != nil {
		t.Fatalf("createLink: %v", err)
	}
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Fatalf("link -> %q (err %v); want %q", got, err, target)
	}

	// Idempotent: re-linking over an existing link succeeds (atomic replace).
	if err := createLink(p); err != nil {
		t.Fatalf("createLink replace: %v", err)
	}

	if err := removeLink(User, link); err != nil {
		t.Fatalf("removeLink: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("link still present after removeLink: %v", err)
	}
	if err := removeLink(User, link); err != nil {
		t.Fatalf("removeLink on an absent link should be a no-op: %v", err)
	}
}

// TestCreateLinkRefusesDirectory checks the guard against a real directory at
// the link path (which would otherwise make ln create the link inside it).
func TestCreateLinkRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sinete-bin")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "occupied")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}

	p := &Plan{Method: User, Target: target, LinkPath: linkDir}
	if err := createLink(p); err == nil {
		t.Fatal("createLink should refuse a directory at the link path")
	}
}
