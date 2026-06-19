// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Linux epoch backend: the registry replay/rollback guard as a TPM 2.0 NV monotonic
// counter, wiring the platform-neutral algorithm in epoch_tpm.go to /dev/tpmrm0. A
// counter is strictly stronger than the macOS keychain item — the TPM tracks a
// global maximum across all counters, so the epoch cannot be rolled back even by
// undefine+redefine (a redefined counter resumes above the global max). The value is
// never "set"; production advances it only via Increment (NV_Increment), which the
// registry.Crypto contract is built around. See PLATFORM-AUDIT.md §4.3 and
// LINUX-TPM-BACKEND.md.
//
// Auth model (v1): owner-hierarchy authorization with an empty password (the default
// storage-hierarchy auth on a personal Linux box / swtpm). On a system that has set a
// non-empty owner auth the define/increment calls fail with a clear TPM error — a
// documented v1 limitation. Anti-rollback holds regardless of who can reach the
// device, because monotonicity is enforced by the TPM, so no custom policy is needed.
package enclave

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// tpmDevice is the TPM 2.0 resource-manager device (kernel-arbitrated access, so
	// concurrent users don't clobber each other's transient handles).
	tpmDevice = "/dev/tpmrm0"
	// epochNVIndex is the owner-defined NV index holding the epoch counter. In the
	// owner range (0x018xxxxx); "7E7E" ≈ sinete.
	epochNVIndex tpm2.TPMHandle = 0x018E7E7E
)

// openTPM opens the resource-manager device.
func openTPM() (transport.TPMCloser, error) {
	t, err := transport.OpenTPM(tpmDevice)
	if err != nil {
		return nil, fmt.Errorf("enclave: open %s: %w", tpmDevice, err)
	}
	return t, nil
}

// ensureEpoch provisions the epoch counter: a TPM NV counter must be defined and
// incremented once before it can be read, so this is a first-class one-time setup
// step (run from EnsureMaster), exactly like provisioning a key — not a workaround.
// Idempotent. Once provisioned, Epoch() reads the counter and Increment() advances
// it; provisioning is simply what makes that first read meaningful. (The macOS
// keychain item is created lazily on first write, so its ensureEpoch is a no-op.)
func ensureEpoch() error {
	t, err := openTPM()
	if err != nil {
		return err
	}
	defer t.Close()
	return tpmEnsureCounter(t, epochNVIndex)
}

func epochGet() (uint64, bool, error) {
	t, err := openTPM()
	if err != nil {
		return 0, false, err
	}
	defer t.Close()
	return tpmCounterGet(t, epochNVIndex)
}

func epochIncrement() (uint64, error) {
	t, err := openTPM()
	if err != nil {
		return 0, err
	}
	defer t.Close()
	return tpmCounterIncrement(t, epochNVIndex)
}

func epochDelete() error {
	t, err := openTPM()
	if err != nil {
		return err
	}
	defer t.Close()
	return tpmCounterDelete(t, epochNVIndex)
}

// epochSet is unsupported on Linux: a TPM NV counter is increment-only. Production
// never calls it (the registry advances the epoch via Increment).
func epochSet(uint64) error {
	return errors.New("enclave: the TPM NV epoch counter is increment-only; SetEpoch is unsupported on Linux")
}
