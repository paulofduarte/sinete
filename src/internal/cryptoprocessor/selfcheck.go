// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package cryptoprocessor

import "github.com/paulofduarte/sinete/internal/registry"

// scratchConfigCrypto signs and verifies with the real master key but reads and
// advances a SEPARATE scratch epoch slot, so the `_enclave-check` config round-trip
// exercises the full sign → verify → epoch → tamper path without touching the
// production replay epoch. This matters on Linux, where the production epoch is a TPM
// NV counter that cannot be rolled back or restored — so the diagnostic must never
// advance it. (On macOS the scratch slot is just a separate keychain item.)
type scratchConfigCrypto struct{ ConfigCrypto }

func (scratchConfigCrypto) Epoch() (uint64, error) {
	v, _, err := scratchEpochGet()
	return v, err
}

func (scratchConfigCrypto) Increment() (uint64, error) { return scratchEpochIncrement() }

// NewScratchConfigCrypto returns a registry.Crypto for diagnostics — master-key
// Sign/Verify over a throwaway epoch — plus a cleanup that removes the scratch epoch.
// It provisions the scratch slot up front (the parity EnsureMaster gives production):
// on Linux this defines+initializes the TPM counter so Epoch() reads a real value; on
// macOS it is a no-op (the keychain item is lazy, so the first read is 0/absent).
// Either way the scratch backend is usable and Increment lands on Epoch()+1.
func NewScratchConfigCrypto() (crypto registry.Crypto, cleanup func() error, err error) {
	if err := scratchEpochEnsure(); err != nil {
		return nil, nil, err
	}
	return scratchConfigCrypto{}, scratchEpochDelete, nil
}
