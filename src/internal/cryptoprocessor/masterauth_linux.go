// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cryptoprocessor

import "github.com/paulofduarte/sinete/internal/pinentry"

// justSetPIN carries a freshly-set PIN to the immediately-following signature so a
// `sinete install` / `config` write that creates the master key and then signs the
// registry does not prompt twice. It is single-use (consumed by the next
// masterSignAuth) and only set in the short-lived CLI process that runs EnsureMaster
// — the agent never creates the master key, so there is no concurrent access.
var justSetPIN []byte

// masterCreateAuth prompts the user to SET a PIN for the config-signing master key.
// The key is created bound to it as its TPM authValue (DA-lockout protected), so the
// same PIN is then required to sign — this is the Linux analogue of the Secure
// Enclave's user-presence ACL on macOS.
func masterCreateAuth() ([]byte, error) {
	pin, err := pinentry.Set("sinete", "Set a PIN to protect sinete's config-signing key. You will need it to change presence settings.")
	if err != nil {
		return nil, err
	}
	justSetPIN = []byte(pin)
	return []byte(pin), nil
}

// masterSignAuth returns the master-key PIN to authorise a config signature, reusing
// a just-set PIN when present, otherwise prompting for it.
func masterSignAuth() ([]byte, error) {
	if justSetPIN != nil {
		pin := justSetPIN
		justSetPIN = nil
		return pin, nil
	}
	pin, err := pinentry.Get("sinete", "Enter your sinete PIN to update the signed presence config.", "PIN:")
	if err != nil {
		return nil, err
	}
	return []byte(pin), nil
}
