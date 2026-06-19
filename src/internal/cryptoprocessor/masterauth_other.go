// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package cryptoprocessor

// Platforms without a presence backend supply no master-key authValue (master-key
// ops aren't reachable here anyway — the epoch is unsupported; see keychain_other.go).
func masterCreateAuth() ([]byte, error) { return nil, nil }
func masterSignAuth() ([]byte, error)   { return nil, nil }
