// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package install

import "errors"

// errUnsupported is returned on platforms with no installer backend (macOS bundle +
// launchd; Linux systemd user service).
var errUnsupported = errors.New("the installer is not supported on this platform")

// PlanInstall is unsupported off macOS.
func PlanInstall() (*Plan, error) { return nil, errUnsupported }

// Install is unsupported off macOS.
func Install(replaceLink, skipLink bool) (*State, error) { return nil, errUnsupported }

// Uninstall is unsupported off macOS.
func Uninstall() error { return errUnsupported }

// IsAdminUser is false off macOS.
func IsAdminUser() bool { return false }
