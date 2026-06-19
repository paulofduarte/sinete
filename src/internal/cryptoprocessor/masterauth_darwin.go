// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cryptoprocessor

// On macOS the master key carries a Secure Enclave user-presence ACL (Touch ID),
// enforced by the OS at sign time, so no authValue is supplied — useBiometrics on
// sks.NewKey sets the ACL and the SE prompts. Both return nil.
func masterCreateAuth() ([]byte, error) { return nil, nil }
func masterSignAuth() ([]byte, error)   { return nil, nil }
