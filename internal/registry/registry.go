// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package registry holds sinete's per-key presence config.
//
// Which keys exist is determined by enumerating the secure element, not by this
// package. Config lives in a single signed file (see Config / config.go):
// registry.json, whose payload is signed by the enclave master key and bound to a
// replay epoch, so tampering or replay is detected and falls back to the built-in
// defaults below.
package registry

import (
	"fmt"
	"regexp"
)

// Presence-config setting names (see `sinete config`). Durations parsed with
// time.ParseDuration; the agent applies the built-in defaults when a value is
// unset.
const (
	PresenceTTL    = "presence-ttl"     // idle window; resets on each signature
	PresenceMaxTTL = "presence-max-ttl" // absolute cap from the first signature
)

// Settings lists the recognised config keys.
var Settings = []string{PresenceTTL, PresenceMaxTTL}

// BuiltinDefaults are the values applied when a setting has no override or global
// default. They are the single source of truth: the agent enforces them and the
// CLI displays them. Keep agent.DefaultIdleTTL / DefaultMaxTTL in sync — a test
// (TestBuiltinDefaultsMatchAgent) verifies they do.
var BuiltinDefaults = map[string]string{
	PresenceTTL:    "10m",
	PresenceMaxTTL: "2h",
}

// BuiltinDefault returns the built-in value for a setting ("" if unknown).
func BuiltinDefault(setting string) string { return BuiltinDefaults[setting] }

// ValidSetting reports whether name is a recognised config key.
func ValidSetting(name string) bool {
	for _, s := range Settings {
		if s == name {
			return true
		}
	}
	return false
}

// nameRE constrains key names to a safe set. A name is reused verbatim as a map
// key, an OpenSSH comment, the sinete-<name>.pub filename component, and an
// allowed_signers principal, so path separators, whitespace, quotes and control
// characters must not appear: it must start with a letter or digit, the rest may
// add '.', '_', '-', '@' and '+'. This makes every name-derived path and shell
// snippet safe by construction (no traversal, no injection).
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]*$`)

// ValidName reports whether name is a safe key name (see nameRE), bounding the
// length so derived filenames stay sane.
func ValidName(name string) error {
	if len(name) > 128 {
		return fmt.Errorf("invalid key name: must be at most 128 characters")
	}
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid key name %q: use letters, digits and . _ - @ + (must start with a letter or digit)", name)
	}
	return nil
}

// Entry describes one enclave key: its human name, the sks label and tag that
// identify it, and its public key. The agent builds these from secure-element
// enumeration — the registry no longer stores keys.
type Entry struct {
	Name      string
	Label     string
	Tag       string
	PublicKey string // OpenSSH authorized_keys line
}
