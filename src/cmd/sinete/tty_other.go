// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package main

// isInteractive is conservatively false on platforms without a real-terminal check
// wired up (macOS and Linux have one — see tty_darwin.go / tty_linux.go), so callers
// stay on the non-interactive (strict) path rather than prompting.
func isInteractive() bool { return false }
