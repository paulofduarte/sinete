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
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	// tpmDevice is the TPM 2.0 resource-manager device (kernel-arbitrated access, so
	// concurrent users don't clobber each other's transient handles).
	tpmDevice = "/dev/tpmrm0"
	// epochNVIndex is the owner-defined NV index holding the production epoch counter.
	// In the owner range (0x018xxxxx); "7E7E" ≈ sinete.
	epochNVIndex tpm2.TPMHandle = 0x018E7E7E
	// scratchNVIndex is a separate counter the _enclave-check diagnostic uses, so the
	// check never advances the production counter (which can't be rolled back).
	scratchNVIndex tpm2.TPMHandle = 0x018E7E6F
)

// openTPM opens the resource-manager device.
func openTPM() (transport.TPMCloser, error) {
	t, err := transport.OpenTPM(tpmDevice)
	if err != nil {
		return nil, fmt.Errorf("enclave: open %s: %w", tpmDevice, err)
	}
	return t, nil
}

// The epoch seam, parameterized by NV index so the production counter (epochNVIndex)
// and the diagnostic's scratch counter (scratchNVIndex) share one implementation.
// Each opens the resource-manager device and delegates to the neutral algorithm in
// epoch_tpm.go.

func ensureEpochAt(index tpm2.TPMHandle) error {
	t, err := openTPM()
	if err != nil {
		return err
	}
	defer t.Close()
	return tpmEnsureCounter(t, index)
}

func epochGetAt(index tpm2.TPMHandle) (uint64, bool, error) {
	t, err := openTPM()
	if err != nil {
		return 0, false, err
	}
	defer t.Close()
	return tpmCounterGet(t, index)
}

func epochIncrementAt(index tpm2.TPMHandle) (uint64, error) {
	t, err := openTPM()
	if err != nil {
		return 0, err
	}
	defer t.Close()
	return tpmCounterIncrement(t, index)
}

func epochDeleteAt(index tpm2.TPMHandle) error {
	t, err := openTPM()
	if err != nil {
		return err
	}
	defer t.Close()
	return tpmCounterDelete(t, index)
}

// ensureEpoch provisions the production epoch counter: a TPM NV counter must be
// defined and incremented once before it can be read, so this is a first-class
// one-time setup step (run from EnsureMaster), exactly like provisioning a key — not
// a workaround. Idempotent. Once provisioned, Epoch() reads the counter and
// Increment() advances it; provisioning is simply what makes that first read
// meaningful. (The macOS keychain item is created lazily on first write, so its
// ensureEpoch is a no-op.)
func ensureEpoch() error              { return ensureEpochAt(epochNVIndex) }
func epochGet() (uint64, bool, error) { return epochGetAt(epochNVIndex) }
func epochIncrement() (uint64, error) { return epochIncrementAt(epochNVIndex) }
func epochDelete() error              { return epochDeleteAt(epochNVIndex) }

// Scratch-epoch seam (diagnostic only): a separate NV counter, so the _enclave-check
// round-trip exercises Epoch/Increment without advancing the production counter.
func scratchEpochEnsure() error              { return ensureEpochAt(scratchNVIndex) }
func scratchEpochGet() (uint64, bool, error) { return epochGetAt(scratchNVIndex) }
func scratchEpochIncrement() (uint64, error) { return epochIncrementAt(scratchNVIndex) }
func scratchEpochDelete() error              { return epochDeleteAt(scratchNVIndex) }
