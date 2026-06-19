// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package presence

import "errors"

// Authenticate is not implemented on platforms without a presence backend.
func Authenticate(string) error {
	return errors.New("user-presence check is not implemented on this platform")
}
