// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// prepareLaunchSession folds the old scripts/sinete-agent.sh wrapper into the
// binary. When launchd starts the agent it captures the session's existing
// SSH_AUTH_SOCK as the upstream (so non-enclave keys are delegated to it) and
// republishes SSH_AUTH_SOCK to our own socket -- both via launchctl in the GUI
// domain. It also redirects this process's stdout/stderr to a log file, since the
// bundled SMAppService plist carries no Standard*Path (those can't bake $HOME).
func prepareLaunchSession(sock string) {
	if up := launchctlGetenv("SSH_AUTH_SOCK"); up != "" && up != sock {
		// First run: record the pre-existing agent. On a KeepAlive restart
		// SSH_AUTH_SOCK is already ours, so we skip and keep the upstream we
		// captured the first time.
		_ = launchctlSetenv("SINETE_UPSTREAM_SOCK", up)
	}
	_ = launchctlSetenv("SSH_AUTH_SOCK", sock)
	if up := launchctlGetenv("SINETE_UPSTREAM_SOCK"); up != "" {
		_ = os.Setenv("SINETE_UPSTREAM_SOCK", up)
	}

	log := filepath.Join(filepath.Dir(sock), "agent.log")
	if f, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		os.Stdout = f
		os.Stderr = f
	}
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
