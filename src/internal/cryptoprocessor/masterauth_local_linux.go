// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !e2e_assume_local

package cryptoprocessor

import (
	"errors"
	"fmt"
	"os"

	"github.com/paulofduarte/sinete/internal/localsession"
)

// requireLocalSession refuses master-key PIN entry from a session that is not
// positively local. This keeps the macOS boundary on Linux: macOS gates the master
// key on Touch ID, which is console-only by construction (it cannot be satisfied over
// SSH), so config signing there is implicitly local. On Linux pinentry will prompt on
// an SSH pty, so a remote user who knows the PIN could otherwise sign config — so we
// confirm via logind/elogind (the same unspoofable signal the agent uses for data
// keys, in internal/localsession) that this process's own session is local, and fail
// closed otherwise. The cost mirrors macOS: presence settings can only be changed at
// the machine.
func requireLocalSession() error {
	local, err := localsession.IsLocalPID(uint32(os.Getpid()))
	if err != nil {
		if localsession.Unavailable(err) {
			return fmt.Errorf("sinete needs systemd-logind or elogind to confirm this is a local session before it will ask for the master-key PIN — install/start one and run sinete at the machine (remote sessions are refused): %w", err)
		}
		return fmt.Errorf("cannot confirm a local session for the master-key PIN prompt; refusing: %w", err)
	}
	if !local {
		return errors.New("refusing to ask for the master-key PIN from a remote session — change sinete's presence config at the machine (as on macOS, where this needs Touch ID)")
	}
	return nil
}
