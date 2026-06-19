// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Linux install (v1, minimal): register the agent as a systemd user service and
// record install.json. No PATH link — on Linux the binary arrives via Nix / a
// package / a manual copy and is invoked directly, so the macOS /usr/local/bin vs
// ~/.local/bin link + launchctl PATH dance has no clean equivalent worth doing for
// v1. Presence is presence-less on Linux v1, so `sinete install` skips presence
// configuration (see cmd/sinete).
package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/paulofduarte/sinete/internal/loginitem"
)

// selfPath returns the absolute path of the running binary (symlinks resolved).
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

// IsAdminUser reports whether the process is root. It is informational only — the
// Linux install is always per-user (a systemd *user* service), regardless.
func IsAdminUser() bool { return os.Geteuid() == 0 }

// PlanInstall reports what an install would do: a per-user systemd service for the
// running binary, with no PATH link in v1.
func PlanInstall() (*Plan, error) {
	exe, err := selfPath()
	if err != nil {
		return nil, err
	}
	return &Plan{Method: User, Target: exe}, nil
}

// Install registers the systemd user service and writes install.json. replaceLink
// and skipLink are ignored (no link in v1).
func Install(_, _ bool) (*State, error) {
	exe, err := selfPath()
	if err != nil {
		return nil, err
	}
	st := &State{Method: User, BundlePath: exe, ConfiguredAt: time.Now().UTC()}
	if err := loginitem.Register(); err != nil {
		return nil, fmt.Errorf("register service: %w", err)
	}
	if err := st.Save(); err != nil {
		_ = loginitem.Unregister()
		return nil, err
	}
	return st, nil
}

// Uninstall unregisters the service, removes any .pub files sinete recorded, and
// deletes install.json. There is no link or PATH entry to remove on Linux.
func Uninstall() error {
	st, err := LoadState()
	if err != nil {
		return err
	}
	var firstErr error
	keep := func(e error) {
		if e != nil && firstErr == nil {
			firstErr = e
		}
	}
	// Only unregister when there is actually a service; if status can't be read,
	// fall back to attempting the unregister (it tolerates an absent unit).
	if status, serr := loginitem.Status(); serr != nil || status != "not found" {
		keep(loginitem.Unregister())
	}
	if st != nil {
		for _, pub := range st.Pubs {
			if e := os.Remove(pub); e != nil && !errors.Is(e, os.ErrNotExist) {
				keep(e)
			}
		}
	}
	keep(RemoveState())
	return firstErr
}
