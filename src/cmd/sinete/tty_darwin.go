// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// isInteractive reports whether stdin is a real terminal, via a TIOCGETA ioctl
// (the same check golang.org/x/term makes). An os.ModeCharDevice test would be too
// broad — /dev/null is also a character device — and would make `sinete install
// < /dev/null` look interactive and apply suggestions when it should stay strict.
func isInteractive() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TIOCGETA)
	return err == nil
}
