// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// This file is the Linux backend for the platform seam that upstream sks does not
// cover: key enumeration and the master config-signing key. Everyday key ops
// (create/open/sign/remove) already go through sks, which on Linux is TPM 2.0 via
// /dev/tpmrm0 (see enclave.go). The replay epoch — a TPM NV monotonic counter —
// lives in epoch_linux.go. See .claude/LINUX-TPM-BACKEND.md.
package enclave

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/facebookincubator/sks"
	"github.com/facebookincubator/sks/diskio"
)

// enumerateKeys lists sinete's keys from the sks on-disk database — the source of
// truth for which TPM keys exist, keyed by sks label — returning each key's label
// and raw ANSI X9.63 public key. `created` is 0: diskio records no creation time,
// which List() (master.go) tolerates. No user presence is involved (public key
// material only), though reading each public key opens the TPM once.
func enumerateKeys(tag string) ([]rawKey, error) {
	db, err := diskio.OpenDB()
	if err != nil {
		return nil, fmt.Errorf("enclave: open sks db: %w", err)
	}
	labels, err := db.List()
	if err != nil {
		return nil, fmt.Errorf("enclave: list sks db: %w", err)
	}
	out := make([]rawKey, 0, len(labels))
	for _, lbl := range labels {
		// sks's internal storage root key is not a user key. sinete's own keys are
		// further filtered by label prefix in List(); other apps' keys sharing the db
		// are dropped there too (non-"sinete-" labels).
		if lbl == diskio.OrgRootKey {
			continue
		}
		pub, ok := sks.FromLabelTag(lbl + ":" + tag).Public().(*ecdsa.PublicKey)
		if !ok || pub == nil {
			// Not a readable P-256 key under this tag — skip rather than fail the
			// whole enumeration.
			continue
		}
		out = append(out, rawKey{label: lbl, pub: ecdsaToANSI(pub)})
	}
	return out, nil
}

// ecdsaToANSI encodes a P-256 public key as ANSI X9.63 (0x04‖X‖Y, 65 bytes) — the
// form macOS returns and master.go's sshPubFromRaw expects.
func ecdsaToANSI(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 65)
	out[0] = 0x04
	pub.X.FillBytes(out[1:33])
	pub.Y.FillBytes(out[33:65])
	return out
}

// createPresenceKey creates the master config-signing key. v1: it is presence-less
// — sks only makes presence-less keys, and the PIN/policy-gated master of
// PLATFORM-AUDIT §4.4 needs the not-yet-built PIN machinery (internal/presence), so
// it is deferred. Config signing plus the NV-counter epoch still carry tamper/replay
// protection; the only delta vs macOS is that a config write isn't gated by a
// local-presence prompt yet. Idempotent: sks.NewKey returns the existing key if the
// label already exists.
func createPresenceKey(label, tag string) error {
	if _, err := sks.NewKey(label, tag, false, false, nil); err != nil {
		return fmt.Errorf("enclave: create master key %q: %w", label, err)
	}
	return nil
}
