// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/paulofduarte/sinete/internal/registry"
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
	prefix := DefaultLabelPrefix + "-"
	out := make([]Listed, 0, len(raws))
	for _, r := range raws {
		// Skip internal keys and any with our tag but an unexpected label: only a
		// "sinete-<name>" label maps to a user key, and the derived name must be a
		// valid sinete name (so callers building paths / authorized_keys lines from
		// it are safe).
		if reserved(r.label) || !strings.HasPrefix(r.label, prefix) {
			continue
		}
		name := strings.TrimPrefix(r.label, prefix)
		if registry.ValidName(name) != nil {
			continue
		}
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
	// Keychain enumeration order is not guaranteed; sort by name so list/export
	// and callers get deterministic output.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
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
	return epochDelete()
}

// EnsureMaster provisions the config-signing prerequisites; it is idempotent.
// Creating them needs no presence; *signing* with the master key does (on macOS).
// It provisions the replay epoch, then creates the master key if absent — both are
// ordinary one-time setup. Provisioning the epoch is a no-op on macOS (the keychain
// item is created lazily on first write); on Linux it defines the TPM NV counter and
// makes it readable (a counter must be incremented once before it can be read), just
// like provisioning any key — see ensureEpoch.
func EnsureMaster() error {
	if err := ensureEpoch(); err != nil {
		return fmt.Errorf("provision epoch: %w", err)
	}
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
	return signer.Sign(rand.Reader, data)
}

// Epoch returns the current registry epoch, and whether it exists yet. The store
// is platform-specific (macOS: a keychain item; Linux: a TPM NV counter).
func Epoch() (uint64, bool, error) { return epochGet() }

// SetEpoch stores an arbitrary registry epoch value. It backs the macOS keychain
// item and the `_enclave-check` diagnostic's restore; a TPM NV counter is
// increment-only, so the Linux backend rejects it. Production code advances the
// epoch via Increment (the registry.Crypto contract), never SetEpoch.
func SetEpoch(v uint64) error { return epochSet(v) }

// DeleteEpoch removes the epoch (keychain delete / NV undefine). It tolerates
// absence and is used to restore the original state after a diagnostic touched it.
func DeleteEpoch() error { return epochDelete() }

// ConfigCrypto adapts the master key and the epoch item to the registry's
// signing needs: it signs and verifies the config envelope and tracks the replay
// epoch. Sign triggers Touch ID (the master key's ACL) and must run on the main
// OS thread; Verify, Epoch and Increment do not prompt. Its method set satisfies
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

// Increment advances the registry epoch by one and returns the new value, with no
// presence prompt. The mechanism is platform-specific (see epochIncrement): macOS
// has no app-accessible hardware counter, so it is a non-atomic read+1+store on the
// keychain item that must be called with the config lock held (as Config.Save does)
// — the keychain has no compare-and-swap; Linux maps it to an atomic hardware TPM
// NV_Increment. See registry.Crypto.
func (ConfigCrypto) Increment() (uint64, error) { return epochIncrement() }

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
