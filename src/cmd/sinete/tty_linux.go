// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// isInteractive reports whether stdin is a real terminal, via a TCGETS ioctl (the
// Linux equivalent of darwin's TIOCGETA; the same check golang.org/x/term makes). A
// character-device test would be too broad — /dev/null is also a character device —
// so `sinete install < /dev/null` correctly looks non-interactive and stays strict.
func isInteractive() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	return err == nil
}
