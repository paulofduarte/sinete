// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package install

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/paulofduarte/sinete/internal/loginitem"
)

// IsAdminUser reports whether the current user belongs to the macOS admin group
// (gid 80). The UI hides Uninstall for a non-admin facing an all-users install,
// since removing the system link needs admin rights.
func IsAdminUser() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, gid := range gids {
		if gid == "80" {
			return true
		}
	}
	return false
}

// binPath is the bundle's sinete executable (the link target).
func binPath(bundlePath string) string {
	return filepath.Join(bundlePath, "Contents", "MacOS", "sinete")
}

// userLinkDir is ~/.local/bin, the per-user link directory.
func userLinkDir(home string) string {
	return filepath.Join(home, ".local", "bin")
}

// PlanInstall computes the link plan for the running bundle without doing
// anything, so the UI can confirm (e.g. an admin prompt or a link conflict).
func PlanInstall() (*Plan, error) {
	app, err := BundlePath()
	if err != nil {
		return nil, err
	}
	if app == "" {
		return nil, errors.New("not running from a sinete.app bundle; install requires the signed bundle")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	p := &Plan{Method: DetectMethod(app, home), Target: binPath(app)}
	if p.Method == Admin {
		p.LinkPath = AdminLinkPath
	} else {
		p.LinkPath = filepath.Join(userLinkDir(home), "sinete")
	}
	inspectLink(p)
	return p, nil
}

// Install registers the login item and (unless skipLink) links `sinete` onto
// PATH and nudges the PATH, then writes the install state. The link is recorded
// in state only when sinete actually created it, so a skipped/declined link is
// never removed on uninstall. With a conflicting link and replaceLink false (and
// skipLink false) it returns ErrLinkConflict, untouched.
func Install(replaceLink, skipLink bool) (*State, error) {
	p, err := PlanInstall()
	if err != nil {
		return nil, err
	}
	st := &State{
		Method:       p.Method,
		BundlePath:   filepath.Dir(filepath.Dir(filepath.Dir(p.Target))),
		ConfiguredAt: time.Now().UTC(),
	}
	if !skipLink {
		if p.LinkConflicts && !replaceLink {
			return nil, ErrLinkConflict
		}
		if err := createLink(p); err != nil {
			return nil, err
		}
		st.LinkPath = p.LinkPath
		if p.Method == User {
			home, _ := os.UserHomeDir()
			dir := userLinkDir(home)
			added, err := ensurePathEntry(dir)
			if err != nil {
				return nil, err
			}
			if added {
				st.PathEntry = dir
			}
		}
	}
	if err := loginitem.Register(); err != nil {
		rollbackLink(st)
		return nil, fmt.Errorf("register login item: %w", err)
	}
	if err := st.Save(); err != nil {
		_ = loginitem.Unregister()
		rollbackLink(st)
		return nil, err
	}
	return st, nil
}

// rollbackLink undoes the filesystem side effects an aborted Install may have
// made (the PATH entry and the link), so a failed install doesn't leave a
// partial state behind — especially one without install.json to guide uninstall.
func rollbackLink(st *State) {
	if st.PathEntry != "" {
		_ = removePathEntry(st.PathEntry)
	}
	if st.LinkPath != "" {
		_ = removeLink(st.Method, st.LinkPath)
	}
}

// Uninstall reverses an install: unregister the login item, remove the link,
// drop the PATH entry, and delete the state file. It does NOT touch enclave keys
// — those are removed separately, with explicit confirmation.
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
	// SMAppService can error when unregistering an item that was never registered
	// (uninstall on an unconfigured machine, or after manual cleanup), so only
	// unregister when it's actually registered. If the status can't be read, fall
	// back to attempting the unregister.
	if status, serr := loginitem.Status(); serr != nil || (status != "not registered" && status != "not found") {
		keep(loginitem.Unregister())
	}
	if st != nil {
		// Only files sinete actually created: a kept (declined) link has an empty
		// LinkPath, and a kept .pub was never recorded in Pubs.
		for _, pub := range st.Pubs {
			if e := os.Remove(pub); e != nil && !errors.Is(e, os.ErrNotExist) {
				keep(e)
			}
		}
		if st.LinkPath != "" {
			keep(removeLink(st.Method, st.LinkPath))
		}
		if st.PathEntry != "" {
			keep(removePathEntry(st.PathEntry))
		}
	}
	keep(RemoveState())
	return firstErr
}

// createLink makes p.LinkPath -> p.Target: an admin-escalated symlink for the
// system path, or a plain ~/.local/bin symlink for the per-user path.
func createLink(p *Plan) error {
	if strings.ContainsAny(p.Target+p.LinkPath, "'\n") {
		return errors.New("refusing to link: a path contains a quote or newline")
	}
	// A real directory at the link path would make `ln -sfn` create the symlink
	// *inside* it (admin path) or the rename fail with an opaque error (user
	// path), so reject it explicitly. Lstat (not Stat) so a symlink-to-directory
	// is still treated as a replaceable link, not a directory.
	if fi, err := os.Lstat(p.LinkPath); err == nil && fi.IsDir() {
		return fmt.Errorf("refusing to link: %s is a directory", p.LinkPath)
	}
	if p.Method == Admin {
		dir := filepath.Dir(p.LinkPath)
		return adminShell(fmt.Sprintf("mkdir -p '%s' && ln -sfn '%s' '%s'", dir, p.Target, p.LinkPath))
	}
	if err := os.MkdirAll(filepath.Dir(p.LinkPath), 0o755); err != nil {
		return err
	}
	// Atomic replace (true ln -sfn semantics): symlink to a temp name in the same
	// directory, then rename it over the target so the link is never missing.
	tmp := p.LinkPath + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(p.Target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, p.LinkPath)
}

func removeLink(method Method, linkPath string) error {
	if strings.ContainsAny(linkPath, "'\n") {
		return errors.New("refusing to unlink: the path contains a quote or newline")
	}
	if method == Admin {
		return adminShell(fmt.Sprintf("rm -f '%s'", linkPath))
	}
	if err := os.Remove(linkPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// adminShell runs a shell command with administrator privileges via osascript,
// which presents the native auth dialog. A cancelled prompt returns an error.
func adminShell(shellCmd string) error {
	// Escape for the AppleScript string literal: backslashes first (so the ones we
	// add for quotes aren't doubled again), then double quotes. Without the
	// backslash pass, a path containing '\' (valid on APFS) would be mangled by
	// AppleScript's own escape handling.
	escaped := strings.ReplaceAll(shellCmd, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	script := `do shell script "` + escaped + `" with administrator privileges`
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("administrator action failed or was cancelled: %s", msg)
	}
	return nil
}

// ensurePathEntry prepends dir to the launchd GUI-session PATH (so terminals
// launched from the GUI find ~/.local/bin/sinete), reporting whether it changed.
func ensurePathEntry(dir string) (bool, error) {
	base := launchctlGetenv("PATH")
	if base == "" {
		base = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	}
	for _, e := range strings.Split(base, ":") {
		if e == dir {
			return false, nil
		}
	}
	if err := launchctlSetenv("PATH", dir+":"+base); err != nil {
		return false, err
	}
	return true, nil
}

func removePathEntry(dir string) error {
	base := launchctlGetenv("PATH")
	if base == "" {
		return nil
	}
	kept := make([]string, 0)
	for _, e := range strings.Split(base, ":") {
		if e != dir {
			kept = append(kept, e)
		}
	}
	return launchctlSetenv("PATH", strings.Join(kept, ":"))
}

func launchctlGetenv(key string) string {
	out, err := exec.Command("launchctl", "getenv", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func launchctlSetenv(key, value string) error {
	return exec.Command("launchctl", "setenv", key, value).Run()
}
