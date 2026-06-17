// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package registry

// lockConfig is a no-op where flock is unavailable. sinete targets macOS and
// Linux (both unix); this keeps the package building elsewhere.
func lockConfig(string) (func(), error) { return func() {}, nil }
