// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package registry holds sinete's per-key presence config.
//
// Which keys exist is determined by enumerating the secure cryptoprocessor, not by this
// package. Config lives in a single signed file (see Config / config.go):
// registry.json, whose payload is signed by the master key and bound to a
// replay epoch. Verification is fail-CLOSED: any missing, tampered, forged or
// stale config makes every setting resolve to 0 — authenticate on every signature
// (the strictest possible value), so losing config can only ever tighten, never
// regress a hardened setting. The values below are setup *suggestions*, never a
// runtime fallback (see Suggested).
package registry

import (
	"fmt"
	"regexp"
)

// Presence-config setting names (see `sinete config`). Durations parsed with
// time.ParseDuration; an unset/unverifiable value resolves to 0 (strict), not to
// any default. presence-max-ttl is a GLOBAL-only ceiling on every presence-ttl.
const (
	PresenceTTL    = "presence-ttl"     // idle window; resets on each signature
	PresenceMaxTTL = "presence-max-ttl" // absolute cap from the first signature (global ceiling)
)

// Settings lists the recognised config keys.
var Settings = []string{PresenceTTL, PresenceMaxTTL}

// suggested holds the values the setup wizard pre-fills (CLI `install` prompt and
// the SwiftUI setup step) so a fresh install isn't prompt-on-every-signature in
// practice. These are SUGGESTIONS ONLY — never a runtime fallback. The enforced
// fallback for a missing/unverifiable setting is 0 (strict); see the package doc.
// Unexported so importers can't mutate it (which would also risk a concurrent
// map read/write panic).
var suggested = map[string]string{
	PresenceTTL:    "10m",
	PresenceMaxTTL: "2h",
}

// Suggested returns the setup-wizard suggestion for a setting ("" if unknown). It
// is not an enforced default — config left unset resolves to 0 (strict).
func Suggested(setting string) string { return suggested[setting] }

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

// Entry describes one cryptoprocessor key: its human name, the sks label and tag that
// identify it, and its public key. The agent builds these from secure-cryptoprocessor
// enumeration — the registry no longer stores keys.
type Entry struct {
	Name      string
	Label     string
	Tag       string
	PublicKey string // OpenSSH authorized_keys line
}
