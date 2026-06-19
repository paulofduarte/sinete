// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux || tpmsim

// The platform-neutral TPM 2.0 NV monotonic-counter algorithm behind the Linux
// epoch backend (epoch_linux.go wires it to /dev/tpmrm0). It only uses go-tpm (pure
// Go on every platform) and operates over a transport.TPM, so it can be exercised
// against the go-tpm simulator in tests (build tag `tpmsim`) without a real device.
// Built on Linux (production, used by epoch_linux.go) or under `tpmsim`; excluded
// from a plain darwin build, where nothing would use it. The epoch design
// (anti-rollback, increment-only, owner auth) is documented in epoch_linux.go and
// PLATFORM-AUDIT.md §4.3.
package enclave

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// errCounterUndefined is returned when an increment is attempted on an NV index that
// has not been defined — production never hits this (EnsureMaster defines it first),
// so it surfaces as a fail-closed epoch mismatch rather than silent trust.
var errCounterUndefined = errors.New("enclave: epoch counter is not defined (run sinete install / a config write first)")

// ownerAuth is a fresh HMAC session authorizing owner-hierarchy NV ops with an empty
// password. A new session per call — session nonces must not be reused.
func ownerAuth() tpm2.Session { return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(nil)) }

// nvCounterPublic is the public template for a monotonic counter at index: an
// owner-readable/writable SHA-256 counter holding 8 bytes, exempt from
// dictionary-attack lockout.
func nvCounterPublic(index tpm2.TPMHandle) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: index,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			NT:         tpm2.TPMNTCounter,
			NoDA:       true,
		},
		DataSize: 8,
	}
}

// nvReadPublic returns index's current Name (needed to authorize ops — it changes
// when the WRITTEN bit flips on the first increment), whether it has been written,
// and whether it exists. A failed read is reported as "does not exist" (commonly an
// undefined handle); a genuine comms failure then surfaces downstream as a
// fail-closed epoch mismatch rather than false trust.
func nvReadPublic(t transport.TPM, index tpm2.TPMHandle) (name tpm2.TPM2BName, written, exists bool, err error) {
	rsp, e := (tpm2.NVReadPublic{NVIndex: index}).Execute(t)
	if e != nil {
		return tpm2.TPM2BName{}, false, false, nil
	}
	pub, e := rsp.NVPublic.Contents()
	if e != nil {
		return tpm2.TPM2BName{}, false, false, e
	}
	return rsp.NVName, pub.Attributes.Written, true, nil
}

// nvReadValue reads the 8-byte counter at index whose current Name is name.
func nvReadValue(t transport.TPM, index tpm2.TPMHandle, name tpm2.TPM2BName) (uint64, error) {
	rsp, err := (tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: ownerAuth()},
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: name},
		Size:       8,
	}).Execute(t)
	if err != nil {
		return 0, fmt.Errorf("enclave: NV read epoch: %w", err)
	}
	if len(rsp.Data.Buffer) != 8 {
		return 0, fmt.Errorf("enclave: epoch counter is %d bytes, want 8", len(rsp.Data.Buffer))
	}
	return binary.BigEndian.Uint64(rsp.Data.Buffer), nil
}

// nvIncrement increments the counter at index (current Name name) by one.
func nvIncrement(t transport.TPM, index tpm2.TPMHandle, name tpm2.TPM2BName) error {
	if _, err := (tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: ownerAuth()},
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: name},
	}).Execute(t); err != nil {
		return fmt.Errorf("enclave: NV increment epoch: %w", err)
	}
	return nil
}

// tpmEnsureCounter provisions the counter at index: it defines the index if absent
// and increments it once if it has never been written, so it becomes readable (a TPM
// counter cannot be read until its first increment). Idempotent.
func tpmEnsureCounter(t transport.TPM, index tpm2.TPMHandle) error {
	_, written, exists, err := nvReadPublic(t, index)
	if err != nil {
		return err
	}
	if !exists {
		if _, err := (tpm2.NVDefineSpace{
			AuthHandle: tpm2.TPMRHOwner,
			PublicInfo: tpm2.New2B(nvCounterPublic(index)),
		}).Execute(t); err != nil {
			return fmt.Errorf("enclave: NV define epoch counter: %w", err)
		}
		written = false
	}
	if !written {
		name, _, _, err := nvReadPublic(t, index)
		if err != nil {
			return err
		}
		if err := nvIncrement(t, index, name); err != nil {
			return fmt.Errorf("enclave: initialize epoch counter: %w", err)
		}
	}
	return nil
}

// tpmCounterGet reads the counter at index. (0, false, nil) when it is absent or
// defined-but-never-incremented (not yet readable) — the same "no epoch yet"
// semantics as an absent macOS keychain item.
func tpmCounterGet(t transport.TPM, index tpm2.TPMHandle) (uint64, bool, error) {
	name, written, exists, err := nvReadPublic(t, index)
	if err != nil {
		return 0, false, err
	}
	if !exists || !written {
		return 0, false, nil
	}
	v, err := nvReadValue(t, index, name)
	if err != nil {
		return 0, false, err
	}
	return v, true, nil
}

// tpmCounterIncrement advances the counter at index by one (an atomic hardware
// NV_Increment) and returns its new value. The Name is re-read after the increment
// because the first one flips the WRITTEN bit. The counter must be provisioned first
// (tpmEnsureCounter); an undefined index is a fail-closed errCounterUndefined.
func tpmCounterIncrement(t transport.TPM, index tpm2.TPMHandle) (uint64, error) {
	name, _, exists, err := nvReadPublic(t, index)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, errCounterUndefined
	}
	if err := nvIncrement(t, index, name); err != nil {
		return 0, err
	}
	name, _, _, err = nvReadPublic(t, index)
	if err != nil {
		return 0, err
	}
	return nvReadValue(t, index, name)
}

// tpmCounterDelete removes the NV index (absence tolerated). The TPM's global
// counter maximum persists, so a future redefine resumes above the old value —
// anti-rollback survives deletion.
func tpmCounterDelete(t transport.TPM, index tpm2.TPMHandle) error {
	name, _, exists, err := nvReadPublic(t, index)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	// NVUndefineSpace is owner-authorized with an HMAC session, so the NV index must
	// be a NamedHandle (its Name feeds the session's command hash).
	if _, err := (tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: name},
	}).Execute(t); err != nil {
		return fmt.Errorf("enclave: NV undefine epoch: %w", err)
	}
	return nil
}
