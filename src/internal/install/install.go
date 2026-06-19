// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package install performs sinete's app-driven setup and teardown: deciding
// whether to put `sinete` on PATH system-wide (admin) or per-user, creating or
// removing that link, registering the launchd login item, and recording what it
// did in a state file so uninstall can reverse exactly those steps. The OS hooks
// (admin escalation, launchctl PATH) live in install_darwin.go.
package install

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Method is how `sinete` is placed on PATH.
type Method string

const (
	// Admin links /usr/local/bin/sinete (on the default PATH; needs an admin
	// prompt). Chosen when the bundle lives in /Applications or outside $HOME.
	Admin Method = "admin"
	// User links ~/.local/bin/sinete (no admin) and nudges that dir onto PATH.
	// Chosen when the bundle lives under the user's home.
	User Method = "user"
)

// AdminLinkPath is the system-wide symlink location.
const AdminLinkPath = "/usr/local/bin/sinete"

// State records what an install created, so uninstall reverses exactly that.
// It lives beside the signed config (registry.json) and is intentionally separate
// from it: uninstall may remove this file while preserving the keys.
type State struct {
	Method       Method    `json:"method"`
	LinkPath     string    `json:"linkPath,omitempty"`  // empty if we kept a pre-existing link
	PathEntry    string    `json:"pathEntry,omitempty"` // dir added to PATH (user installs)
	Pubs         []string  `json:"pubs,omitempty"`      // .pub files we wrote (uninstall removes these)
	BundlePath   string    `json:"bundlePath"`
	ConfiguredAt time.Time `json:"configuredAt"`
}

// StatePath returns $XDG_CONFIG_HOME/sinete/install.json (beside registry.json),
// falling back to ~/.config/sinete/install.json.
func StatePath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "sinete", "install.json"), nil
}

// LoadState reads the install state, returning (nil, nil) if not configured.
func LoadState() (*State, error) {
	path, err := StatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save writes the install state atomically.
func (s *State) Save() error {
	path, err := StatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RemoveState deletes the install state file. Absence is not an error.
func RemoveState() error {
	path, err := StatePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// BundlePath returns the .app bundle directory the running binary lives in
// (…/sinete.app/Contents/MacOS/sinete → …/sinete.app), or "" if it is not run
// from a bundle (e.g. a bare dev binary).
func BundlePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	macos := filepath.Dir(exe)
	contents := filepath.Dir(macos)
	app := filepath.Dir(contents)
	if filepath.Base(macos) == "MacOS" && filepath.Base(contents) == "Contents" && strings.HasSuffix(app, ".app") {
		return app, nil
	}
	return "", nil
}

// DetectMethod picks the install method from the bundle path: Admin when the
// bundle is in /Applications or outside the user's home, User when it lives under
// home. home is the user's home directory (os.UserHomeDir).
func DetectMethod(bundlePath, home string) Method {
	if strings.HasPrefix(bundlePath, "/Applications/") {
		return Admin
	}
	if home != "" && (bundlePath == home || strings.HasPrefix(bundlePath, home+string(filepath.Separator))) {
		return User
	}
	return Admin
}

// RecordPub adds a .pub path that sinete wrote to the install state, so uninstall
// removes only the files sinete created. It is a no-op when there is no install
// state (e.g. ssh-setup run standalone, before any install).
func RecordPub(path string) error {
	st, err := LoadState()
	if err != nil || st == nil {
		return err
	}
	for _, p := range st.Pubs {
		if p == path {
			return nil
		}
	}
	st.Pubs = append(st.Pubs, path)
	return st.Save()
}

// Plan is the link an install would create, for the UI to confirm before any
// privileged action. LinkConflicts is true when LinkPath already points
// somewhere other than the intended target.
type Plan struct {
	Method        Method `json:"method"`
	LinkPath      string `json:"linkPath"`
	Target        string `json:"target"`
	LinkExists    bool   `json:"linkExists"`
	LinkConflicts bool   `json:"linkConflicts"`
}

// inspectLink fills in the existence/conflict fields for a planned link.
func inspectLink(p *Plan) {
	fi, err := os.Lstat(p.LinkPath)
	if err != nil {
		return
	}
	p.LinkExists = true
	if fi.Mode()&os.ModeSymlink != 0 {
		if dest, err := os.Readlink(p.LinkPath); err == nil {
			// Resolve a relative target against the link's directory before
			// comparing, so a relatively-spelled symlink that points at the same
			// file isn't a false conflict (which would trigger a needless,
			// potentially destructive "Replace" prompt).
			if !filepath.IsAbs(dest) {
				dest = filepath.Join(filepath.Dir(p.LinkPath), dest)
			}
			p.LinkConflicts = !sameTarget(dest, p.Target)
			return
		}
	}
	// A non-symlink file occupying the path is a conflict.
	p.LinkConflicts = true
}

// sameTarget reports whether two paths refer to the same link target: by cleaned
// path, else by underlying file identity (os.Stat follows symlinks), so a
// differently-spelled path that resolves to the same file isn't a conflict.
func sameTarget(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// ErrLinkConflict is returned by Install when the link path is occupied by a
// different target and replace was not requested; the UI should confirm, then
// retry with replace=true.
var ErrLinkConflict = errors.New("a different file already occupies the sinete link path")
