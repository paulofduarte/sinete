// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// On Linux the agent runs as a systemd *user* service — the per-user analogue of
// the macOS launchd login item — managed with `systemctl --user`. The unit file
// lives at $XDG_CONFIG_HOME/systemd/user/<AgentLabel>.service and runs the same
// binary that performed the install. No cgo.
//
// To keep the agent running across logout / on a headless box, the user runs
// `loginctl enable-linger`; that is documented, not done here.
package loginitem

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// unitName is the systemd unit filename (AgentLabel is the shared job label).
const unitName = AgentLabel + ".service"

// unitPath returns $XDG_CONFIG_HOME/systemd/user/<unit>, falling back to
// ~/.config/systemd/user/<unit> (matching install.StatePath's resolution).
func unitPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "systemd", "user", unitName), nil
}

// systemctl runs `systemctl --user <args>` and returns its combined output. A
// missing systemctl (no systemd) yields a clear error.
func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", errors.New("systemd not available (systemctl --user); install the agent's service manually")
		}
		return strings.TrimSpace(string(out)), err
	}
	return strings.TrimSpace(string(out)), nil
}

// selfPath returns the absolute path of the running binary (symlinks resolved), for
// the unit's ExecStart.
func selfPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	return exe, nil
}

// unitContent renders the service unit. ExecStart runs the agent enclave-only (no
// --launchd: that macOS flag captures the session's SSH_AUTH_SOCK as the delegation
// upstream and redirects logs, neither of which applies under systemd — journald
// handles logs). The exe path is quoted so a path with spaces still parses.
func unitContent(exe string) string {
	return fmt.Sprintf(`[Unit]
Description=sinete SSH agent (hardware-backed)

[Service]
ExecStart="%s" agent
Restart=on-failure

[Install]
WantedBy=default.target
`, exe)
}

// Register writes the user unit and enables+starts it.
func Register() error {
	exe, err := selfPath()
	if err != nil {
		return err
	}
	path, err := unitPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(unitContent(exe)), 0o600); err != nil {
		return err
	}
	if out, err := systemctl("daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, out)
	}
	if out, err := systemctl("enable", "--now", unitName); err != nil {
		return fmt.Errorf("enable %s: %w: %s", unitName, err, out)
	}
	return nil
}

// Unregister stops/disables the service and removes the unit file. Each step
// tolerates the service or file already being gone.
func Unregister() error {
	// disable --now stops and disables; ignore its error (it fails if the unit was
	// never loaded), since removing the file below is the authoritative cleanup.
	_, _ = systemctl("disable", "--now", unitName)
	path, err := unitPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, _ = systemctl("daemon-reload")
	return nil
}

// Status reports "enabled", "disabled", or "not found" (no unit file). It mirrors
// the darwin vocabulary enough for Uninstall to decide whether to unregister.
func Status() (string, error) {
	path, err := unitPath()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "not found", nil
		}
		return "", err
	}
	// The unit file exists, so it is at least registered — never "not found" here.
	// is-enabled prints the state on stdout and exits non-zero for disabled/static, so
	// the printed word is what we want regardless of exit status. But if systemctl
	// itself fails (no systemd, not on PATH) it prints nothing; surface that error so
	// Uninstall falls back to a best-effort Unregister rather than skipping it and
	// leaving the unit file behind.
	out, serr := systemctl("is-enabled", unitName)
	switch out {
	case "enabled", "enabled-runtime":
		return "enabled", nil
	case "":
		if serr != nil {
			return "", fmt.Errorf("systemctl is-enabled %s: %w", unitName, serr)
		}
		return "disabled", nil
	default:
		return "disabled", nil
	}
}
