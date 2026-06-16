// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package presence

import "errors"

// Authenticate is not yet implemented off macOS (Linux TPM presence is planned).
func Authenticate(string) error {
	return errors.New("user-presence check is not implemented on this platform")
}
