// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package loginitem

import "errors"

// errUnsupported is returned on platforms with no service backend (macOS uses
// SMAppService; Linux uses a systemd user service).
var errUnsupported = errors.New("login item management is not supported on this platform")

// Register is unsupported off macOS.
func Register() error { return errUnsupported }

// Unregister is unsupported off macOS.
func Unregister() error { return errUnsupported }

// Status is unsupported off macOS.
func Status() (string, error) { return "", errUnsupported }
