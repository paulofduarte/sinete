// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Reserved internal names. The master key signs the config registry; the epoch
// item guards it against replay. Both are hidden from list/export/agent List.
const (
	// MasterLabel is the sks label of the internal config-signing key. The leading
	// underscore keeps it out of the user's namespace (ValidName forbids it).
	MasterLabel = DefaultLabelPrefix + "-_master"
	// EpochService/EpochAccount identify the presence-less keychain item holding
	// the registry epoch (a monotonic counter; see .claude/SIGNED-REGISTRY.md).
	EpochService = Tag
	EpochAccount = "_epoch"
)

// rawKey is one enumerated keychain key: its sks label, the raw ANSI X9.63
// public key (0x04‖X‖Y for P-256), and its creation time (Unix seconds, 0 if
// unavailable). Populated by the platform layer (keychain_darwin.go / _other.go).
type rawKey struct {
	label   string
	pub     []byte
	created int64
}

// Listed is a key discovered by enumerating the secure element — the source of
// truth for which keys exist (the registry no longer stores them).
type Listed struct {
	Name      string
	Label     string
	PublicKey ssh.PublicKey
	Created   time.Time
}

// reserved reports whether a label is one of sinete's internal keys, which must
// never surface as a user key.
func reserved(label string) bool {
	return label == MasterLabel
}

// List enumerates sinete's user keys from the secure element, skipping internal
// keys. It requires no user presence (public attributes only).
func List() ([]Listed, error) {
	raws, err := enumerateKeys(Tag)
	if err != nil {
		return nil, err
	}
	out := make([]Listed, 0, len(raws))
	for _, r := range raws {
		if reserved(r.label) {
			continue
		}
		name := strings.TrimPrefix(r.label, DefaultLabelPrefix+"-")
		pub, err := sshPubFromRaw(r.pub)
		if err != nil {
			return nil, fmt.Errorf("enclave: key %q: %w", r.label, err)
		}
		l := Listed{Name: name, Label: r.label, PublicKey: pub}
		if r.created > 0 {
			l.Created = time.Unix(r.created, 0).UTC()
		}
		out = append(out, l)
	}
	return out, nil
}

// Find returns the enumerated user key with the given name.
func Find(name string) (Listed, bool, error) {
	keys, err := List()
	if err != nil {
		return Listed{}, false, err
	}
	for _, k := range keys {
		if k.Name == name {
			return k, true, nil
		}
	}
	return Listed{}, false, nil
}

// RemoveMaster deletes the internal master key and the epoch item. Used only by
// uninstall --remove-keys. Removing the master key is best-effort (it may already
// be gone); the epoch item delete tolerates absence.
func RemoveMaster() error {
	_ = masterKey().Remove()
	return keychainItemDelete(EpochService, EpochAccount)
}

// EnsureMaster creates the presence-enforced master key if it does not yet
// exist; it is idempotent. Creating it needs no presence; *signing* with it does.
func EnsureMaster() error {
	if _, err := masterKey().PublicKey(); err == nil {
		return nil // already present
	}
	if err := createPresenceKey(MasterLabel, Tag); err != nil {
		// Tolerate a concurrent creator: if the key now exists, another process
		// won the race and that is success, not a duplicate-item failure.
		if _, perr := masterKey().PublicKey(); perr == nil {
			return nil
		}
		return err
	}
	return nil
}

// masterKey opens the master key via sks (by label+tag). Signing through it
// triggers the user-presence prompt the key's ACL requires.
func masterKey() *Key { return OpenLabelTag(MasterLabel, Tag) }

// MasterPublicKey returns the master key's public key (for verifying signed
// config). Reading a public key requires no presence.
func MasterPublicKey() (ssh.PublicKey, error) {
	pub, err := masterKey().PublicKey()
	if err != nil {
		return nil, fmt.Errorf("enclave: master key not available (run a config write to create it): %w", err)
	}
	return pub, nil
}

// MasterSign signs data with the master key (the ssh signer hashes it
// internally). This triggers Touch ID — the key's user-presence ACL — so it must
// run on the main OS thread. Verify with MasterPublicKey().Verify(data, sig).
func MasterSign(data []byte) (*ssh.Signature, error) {
	signer, err := masterKey().Signer()
	if err != nil {
		return nil, err
	}
	return signer.Sign(nil, data)
}

// Epoch returns the current registry epoch, and whether the item exists yet.
func Epoch() (uint64, bool, error) {
	b, err := keychainItemGet(EpochService, EpochAccount)
	if err != nil {
		return 0, false, err
	}
	if b == nil {
		return 0, false, nil
	}
	if len(b) != 8 {
		return 0, false, fmt.Errorf("enclave: epoch item is %d bytes, want 8", len(b))
	}
	return binary.BigEndian.Uint64(b), true, nil
}

// SetEpoch stores the registry epoch (8-byte big-endian).
func SetEpoch(v uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return keychainItemSet(EpochService, EpochAccount, b[:])
}

// ConfigCrypto adapts the master key and the epoch item to the registry's
// signing needs: it signs and verifies the config envelope and tracks the replay
// epoch. Sign triggers Touch ID (the master key's ACL) and must run on the main
// OS thread; Verify, Epoch and SetEpoch do not prompt. Its method set satisfies
// registry.Crypto structurally (no import cycle).
type ConfigCrypto struct{}

// Sign signs the config payload with the master key (prompts for presence),
// returning the ssh.Signature in wire form.
func (ConfigCrypto) Sign(payload []byte) ([]byte, error) {
	sig, err := MasterSign(payload)
	if err != nil {
		return nil, err
	}
	return ssh.Marshal(*sig), nil
}

// Verify reports whether sig is a valid master-key signature over payload. It
// reads the master public key (no prompt) and returns false on any failure.
func (ConfigCrypto) Verify(payload, sig []byte) bool {
	pub, err := MasterPublicKey()
	if err != nil {
		return false
	}
	var s ssh.Signature
	if err := ssh.Unmarshal(sig, &s); err != nil {
		return false
	}
	return pub.Verify(payload, &s) == nil
}

// Epoch returns the current registry epoch (0 if the item does not exist yet).
func (ConfigCrypto) Epoch() (uint64, error) {
	v, _, err := Epoch()
	return v, err
}

// SetEpoch stores the registry epoch.
func (ConfigCrypto) SetEpoch(v uint64) error { return SetEpoch(v) }

// sshPubFromRaw parses an ANSI X9.63 uncompressed P-256 point (0x04‖X‖Y, 65
// bytes) into an ssh.PublicKey.
func sshPubFromRaw(raw []byte) (ssh.PublicKey, error) {
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("unexpected public key encoding (%d bytes)", len(raw))
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}
	return ssh.NewPublicKey(pub)
}
