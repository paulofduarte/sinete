// Package agent implements a read-only ssh-agent serving sinete's enclave keys.
//
// It satisfies golang.org/x/crypto/ssh/agent.Agent but only answers List and
// Sign: List reports the registry's public keys without touching hardware, and
// Sign performs the signature in the secure element (firing the user-presence
// prompt). Key lifecycle is the CLI's job, so the mutating operations report
// that they are unsupported.
package agent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/paulofduarte/sinete/internal/enclave"
	"github.com/paulofduarte/sinete/internal/registry"
	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

var errReadOnly = errors.New("sinete agent is read-only; manage keys with the sinete CLI")

// Agent serves the keys recorded in a registry over the ssh-agent protocol.
type Agent struct {
	prefix string
	reg    *registry.Registry
}

var _ xagent.Agent = (*Agent)(nil)

// New returns an agent serving the keys in reg, opened under the given label prefix.
func New(prefix string, reg *registry.Registry) *Agent {
	return &Agent{prefix: prefix, reg: reg}
}

// List reports the registry's public keys. It does not touch the secure element.
func (a *Agent) List() ([]*xagent.Key, error) {
	entries := a.reg.List()
	keys := make([]*xagent.Key, 0, len(entries))
	for _, e := range entries {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("registry key %q: %w", e.Name, err)
		}
		keys = append(keys, &xagent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: e.Name})
	}
	return keys, nil
}

// Sign signs data with the enclave key whose public key matches key, prompting
// for user presence.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	name, ok := a.nameFor(key)
	if !ok {
		return nil, errors.New("no matching key")
	}
	signer, err := enclave.Open(a.prefix, name).Signer()
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand.Reader, data)
}

// nameFor returns the registry name whose public key matches key.
func (a *Agent) nameFor(key ssh.PublicKey) (string, bool) {
	want := key.Marshal()
	for _, e := range a.reg.List() {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
		if err != nil {
			continue
		}
		if bytes.Equal(pub.Marshal(), want) {
			return e.Name, true
		}
	}
	return "", false
}

// The remaining operations are unsupported: sinete is a read-only agent.
func (a *Agent) Add(xagent.AddedKey) error      { return errReadOnly }
func (a *Agent) Remove(ssh.PublicKey) error     { return errReadOnly }
func (a *Agent) RemoveAll() error               { return errReadOnly }
func (a *Agent) Lock([]byte) error              { return errReadOnly }
func (a *Agent) Unlock([]byte) error            { return errReadOnly }
func (a *Agent) Signers() ([]ssh.Signer, error) { return nil, errReadOnly }
