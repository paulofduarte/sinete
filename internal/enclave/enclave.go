// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package enclave wraps facebookincubator/sks to create, open, sign with and
// remove sinete's secure-element keys.
//
// It maps a human name to the (label, tag) that sks identifies a key by, and
// exposes keys as ssh.Signer / ssh.PublicKey so the agent and CLI never touch
// platform crypto directly. Algorithm is always ECDSA P-256 (a Secure Enclave
// constraint).
package enclave

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/facebookincubator/sks"
	"golang.org/x/crypto/ssh"
)

const (
	// DefaultLabelPrefix is prepended to a key's name to form its sks label.
	DefaultLabelPrefix = "sinete"
	// Tag is the sks application tag shared by all sinete keys.
	Tag = "dev.sinete"
)

// Key is a secure-element key identified by a human name.
type Key struct {
	name  string
	label string
	inner sks.Key
}

func label(prefix, name string) string { return prefix + "-" + name }

// Create generates a new key for name. When requirePresence is set, signing
// requires user presence (Touch ID, or the device passcode where biometrics is
// unavailable).
func Create(prefix, name string, requirePresence bool) (*Key, error) {
	l := label(prefix, name)
	k, err := sks.NewKey(l, Tag, requirePresence, false, nil)
	if err != nil {
		return nil, fmt.Errorf("create key %q: %w", name, err)
	}
	return &Key{name: name, label: l, inner: k}, nil
}

// Open references an existing key for name without creating one.
func Open(prefix, name string) *Key {
	l := label(prefix, name)
	return &Key{name: name, label: l, inner: sks.FromLabelTag(l + ":" + Tag)}
}

// OpenLabelTag references an existing key by its exact sks label and tag rather
// than recomputing them from a name, so callers (the agent) can use the values
// recorded in the registry as authoritative.
func OpenLabelTag(label, tag string) *Key {
	return &Key{label: label, inner: sks.FromLabelTag(label + ":" + tag)}
}

// Name returns the human name of the key.
func (k *Key) Name() string { return k.name }

// Label returns the sks label of the key.
func (k *Key) Label() string { return k.label }

// ident returns a human-meaningful identifier for diagnostics: the name when
// set, otherwise the sks label (e.g. for keys opened via OpenLabelTag).
func (k *Key) ident() string {
	if k.name != "" {
		return k.name
	}
	return k.label
}

// PublicKey returns the SSH public key. It reads the public half from the
// secure element but requires no user presence.
func (k *Key) PublicKey() (ssh.PublicKey, error) {
	pub, ok := k.inner.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key %q: secure element returned no ECDSA public key", k.ident())
	}
	return ssh.NewPublicKey(pub)
}

// Signer returns an ssh.Signer backed by the secure element. Producing a
// signature fires the user-presence prompt.
func (k *Key) Signer() (ssh.Signer, error) {
	return ssh.NewSignerFromSigner(k.inner)
}

// Remove deletes the key from the secure element.
func (k *Key) Remove() error {
	return k.inner.Remove()
}
