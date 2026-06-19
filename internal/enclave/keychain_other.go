// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package enclave

import "errors"

// errUnsupported is returned on platforms with no secure-element backend yet (the
// key enumeration, presence-enforced master key, and replay epoch). macOS is cgo +
// Security.framework (keychain_darwin.go); Linux is go-tpm (keychain_linux.go).
var errUnsupported = errors.New("enclave: secure-element backend is not implemented on this platform")

func enumerateKeys(string) ([]rawKey, error) { return nil, errUnsupported }
func createPresenceKey(_, _ string) error    { return errUnsupported }
func ensureEpoch() error                     { return errUnsupported }
func epochGet() (uint64, bool, error)        { return 0, false, errUnsupported }
func epochIncrement() (uint64, error)        { return 0, errUnsupported }
func epochDelete() error                     { return errUnsupported }

func scratchEpochEnsure() error              { return errUnsupported }
func scratchEpochGet() (uint64, bool, error) { return 0, false, errUnsupported }
func scratchEpochIncrement() (uint64, error) { return 0, errUnsupported }
func scratchEpochDelete() error              { return errUnsupported }
