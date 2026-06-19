// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cryptoprocessor

import (
	"fmt"

	"github.com/paulofduarte/sinete/internal/pinentry"
)

// justSetPIN carries a freshly-set PIN to the immediately-following signature so a
// `sinete install` / `config` write that creates the master key and then signs the
// registry does not prompt twice. It is set by cacheMasterPIN only AFTER a successful
// creation (so a concurrent-creator race never caches a PIN that isn't the key's),
// single-use (consumed by the next masterSignAuth), and only ever set in the
// short-lived CLI process that runs EnsureMaster — the agent never creates the master
// key, so there is no concurrent access.
var justSetPIN []byte

// masterCreateAuth prompts the user to SET a PIN for the config-signing master key.
// The key is created bound to it as its TPM authValue (DA-lockout protected), so the
// same PIN is then required to sign — this is the Linux analogue of the Secure
// Enclave's user-presence ACL on macOS.
func masterCreateAuth() ([]byte, error) {
	if err := requireLocalSession(); err != nil {
		return nil, err
	}
	pin, err := pinentry.Set("sinete", "Set a PIN to protect sinete's config-signing key. You will need it to change presence settings.")
	if err != nil {
		return nil, err
	}
	return []byte(pin), nil
}

// cacheMasterPIN records a just-set PIN for reuse by the immediately-following sign.
// EnsureMaster calls it only after the key was actually created with this PIN.
func cacheMasterPIN(pin []byte) { justSetPIN = pin }

// masterSignError adds a remediation hint to a failed master-key signature. The most
// common causes are a wrong PIN or a master key created by an earlier version with no
// PIN (empty authValue) that now rejects the PIN we supply — but a TPM/device error
// is also possible, so the hint is phrased as a possibility and the underlying error
// is wrapped so the real cause stays visible.
func masterSignError(err error) error {
	return fmt.Errorf("master sign failed (often a wrong PIN, or a master key created before PIN support that must be re-provisioned): %w", err)
}

// masterSignAuth returns the master-key PIN to authorise a config signature, reusing
// a just-set PIN when present, otherwise prompting for it.
func masterSignAuth() ([]byte, error) {
	if err := requireLocalSession(); err != nil {
		return nil, err
	}
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
