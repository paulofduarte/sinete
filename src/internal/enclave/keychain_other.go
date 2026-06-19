// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package enclave

import "errors"

// errUnsupported is returned on platforms with no replay-epoch backend yet. Key
// enumeration and the master key now go through sks directly (see master.go); only
// the epoch remains platform-specific — macOS is a keychain item (keychain_darwin.go),
// Linux a TPM NV counter (epoch_linux.go).
var errUnsupported = errors.New("enclave: replay-epoch backend is not implemented on this platform")

func ensureEpoch() error              { return errUnsupported }
func epochGet() (uint64, bool, error) { return 0, false, errUnsupported }
func epochIncrement() (uint64, error) { return 0, errUnsupported }
func epochDelete() error              { return errUnsupported }

func scratchEpochEnsure() error              { return errUnsupported }
func scratchEpochGet() (uint64, bool, error) { return 0, false, errUnsupported }
func scratchEpochIncrement() (uint64, error) { return 0, errUnsupported }
func scratchEpochDelete() error              { return errUnsupported }
