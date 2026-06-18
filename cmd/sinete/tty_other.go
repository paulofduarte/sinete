// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

// isInteractive is conservatively false on platforms where the interactive setup
// flow isn't wired up (the secure-element ops are macOS-only today), so callers
// stay on the non-interactive (strict) path rather than prompting.
func isInteractive() bool { return false }
