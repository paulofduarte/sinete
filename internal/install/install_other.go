// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package install

import "errors"

// errUnsupported is returned off macOS, where the app installer does not apply.
var errUnsupported = errors.New("the app installer is only supported on macOS")

// PlanInstall is unsupported off macOS.
func PlanInstall() (*Plan, error) { return nil, errUnsupported }

// Install is unsupported off macOS.
func Install(bool) (*State, error) { return nil, errUnsupported }

// Uninstall is unsupported off macOS.
func Uninstall() error { return errUnsupported }
