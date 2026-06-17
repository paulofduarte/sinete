// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/paulofduarte/sinete/internal/loginitem"
)

// launchUIIfDoubleClicked hands off to the bundled SwiftUI panel (sinete-ui, a
// sibling in Contents/MacOS) when this binary was double-clicked in Finder: no
// arguments, not the launchd agent, and no controlling terminal. It execs the UI
// in place and does not return on success; it returns (doing nothing) when this
// is a normal CLI run or there is no UI binary, so `sinete` in a terminal still
// prints usage.
func launchUIIfDoubleClicked() {
	if len(os.Args) >= 2 || os.Getenv("XPC_SERVICE_NAME") == loginitem.AgentLabel {
		return
	}
	// A terminal run has a controlling terminal; a Finder double-click (or `open`)
	// does not. We can't key off stdout being a char device -- a Finder launch
	// wires stdio to /dev/null, which IS a char device -- so we probe /dev/tty,
	// which opens only when the process has a controlling terminal.
	if f, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0); err == nil {
		_ = f.Close()
		return // controlling terminal present: a CLI run, show usage
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, e := filepath.EvalSymlinks(exe); e == nil {
		exe = resolved
	}
	ui := filepath.Join(filepath.Dir(exe), "sinete-ui")
	if _, err := os.Stat(ui); err != nil {
		return
	}
	_ = syscall.Exec(ui, []string{ui}, os.Environ())
}

// prepareLaunchSession runs when launchd starts the agent. It only redirects
// stdout/stderr to a log file, since the bundled SMAppService plist carries no
// Standard*Path (those can't bake $HOME).
//
// It does NOT touch SSH_AUTH_SOCK: macOS injects the system agent's secure socket
// into every GUI process and `launchctl setenv` can't reliably override it, so
// clients reach sinete via IdentityAgent (or an explicit SSH_AUTH_SOCK). The
// delegation upstream is resolved in cmdAgent from the inherited SSH_AUTH_SOCK,
// so nothing needs republishing or capturing here.
func prepareLaunchSession(sock string) {
	log := filepath.Join(filepath.Dir(sock), "agent.log")
	if f, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		os.Stdout = f
		os.Stderr = f
	}
}
