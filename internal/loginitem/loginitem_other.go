// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package loginitem

import "errors"

// errUnsupported is returned off macOS, where SMAppService does not exist.
var errUnsupported = errors.New("login item management is only supported on macOS")

// Register is unsupported off macOS.
func Register() error { return errUnsupported }

// Unregister is unsupported off macOS.
func Unregister() error { return errUnsupported }

// Status is unsupported off macOS.
func Status() (string, error) { return "", errUnsupported }
