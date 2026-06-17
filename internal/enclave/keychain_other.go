// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package enclave

import "errors"

// errUnsupported is returned off macOS, where the Security-framework layer (key
// enumeration, the presence-enforced master key, the epoch item) has no backend
// yet. Linux/TPM support is planned (see .claude/SIGNED-REGISTRY.md).
var errUnsupported = errors.New("enclave: secure-element keychain ops are not implemented on this platform")

func enumerateKeys(string) ([]rawKey, error)      { return nil, errUnsupported }
func createPresenceKey(_, _ string) error         { return errUnsupported }
func keychainItemGet(_, _ string) ([]byte, error) { return nil, errUnsupported }
func keychainItemSet(_, _ string, _ []byte) error { return errUnsupported }
func keychainItemDelete(_, _ string) error        { return errUnsupported }
