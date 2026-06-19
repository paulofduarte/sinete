// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import "testing"

// PlanInstall on Linux describes a per-user service for the running binary, with no
// PATH link in v1. (Install/Uninstall drive systemctl --user, which needs a user
// session bus; the QEMU integration test's minimal initramfs has none, so the service
// path is not yet exercised end-to-end — only this plan + the loginitem unit-rendering
// tests cover it. A fuller-userland VM is needed for the service e2e.)
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
