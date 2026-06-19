// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package registry

// lockConfig is a no-op on platforms without flock (non-unix); it only keeps the
// package building there. sinete's secure-element backends are unix-only, so the
// lock that actually matters is the real flock build in lock_unix.go.
func lockConfig(string) (func(), error) { return func() {}, nil }
