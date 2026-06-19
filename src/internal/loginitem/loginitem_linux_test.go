// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loginitem

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUnitContent(t *testing.T) {
	u := unitContent("/opt/sinete/bin/sinete")
	for _, want := range []string{
		`ExecStart="/opt/sinete/bin/sinete" agent`, // quoted path, no --launchd
		"Restart=on-failure",
		"WantedBy=default.target",
		"[Service]",
		"[Install]",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q:\n%s", want, u)
		}
	}
	if strings.Contains(u, "--launchd") {
		t.Errorf("Linux unit must not pass --launchd (macOS-only):\n%s", u)
	}
}

func TestUnitPathHonoursXDG(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	got, err := unitPath()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "systemd", "user", "me.paulofduarte.sinete.agent.service")
	if got != want {
		t.Errorf("unitPath = %q, want %q", got, want)
	}
}
