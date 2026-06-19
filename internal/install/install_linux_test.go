// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import "testing"

// PlanInstall on Linux describes a per-user service for the running binary, with no
// PATH link in v1. (Install/Uninstall drive systemctl --user and are exercised
// end-to-end in the QEMU integration test, which has a real user session bus.)
func TestPlanInstall(t *testing.T) {
	p, err := PlanInstall()
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != User {
		t.Errorf("method = %q, want %q", p.Method, User)
	}
	if p.Target == "" {
		t.Error("target should be the binary path, got empty")
	}
	if p.LinkPath != "" {
		t.Errorf("v1 Linux install creates no link, got LinkPath = %q", p.LinkPath)
	}
}
