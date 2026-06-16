// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package agent implements sinete's ssh-agent (Model B).
//
// It advertises every key in the registry — so ssh/git use them with no manual
// step, like a normal agent — and enforces user presence at *sign* time: the
// first signature with a key prompts for Touch ID, and subsequent signatures are
// silent until that key's presence window (a TTL) lapses, after which the next
// signature prompts again. The keys are presence-less in the secure element; the
// agent holds only enclave-backed signer *handles*, never key material, and every
// signature is computed in hardware.
package agent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/paulofduarte/sinete/internal/enclave"
	"github.com/paulofduarte/sinete/internal/registry"
	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

var (
	errUnsupported = errors.New("sinete agent is read-only; manage keys with the sinete CLI")
	errNotFound    = errors.New("agent: no matching key")
)

// SignerSource resolves an enclave key (by its sks label and tag) to a signer.
// It is an interface so the agent's presence/TTL logic is testable without the
// secure element; production uses EnclaveSource.
type SignerSource interface {
	Signer(label, tag string) (ssh.Signer, error)
}

// EnclaveSource is the production SignerSource, backed by the secure element.
type EnclaveSource struct{}

// Signer returns an enclave-backed ssh.Signer for the given label and tag.
func (EnclaveSource) Signer(label, tag string) (ssh.Signer, error) {
	return enclave.OpenLabelTag(label, tag).Signer()
}

// Agent serves the registry's keys over the ssh-agent protocol, gating user
// presence at sign time. It satisfies golang.org/x/crypto/ssh/agent.Agent.
type Agent struct {
	reg     *registry.Registry
	signers SignerSource
	present func(reason string) error
	ttl     time.Duration

	mu    sync.Mutex
	until map[string]time.Time // key name -> presence-authenticated until
	jobs  chan signJob
}

type signJob struct {
	entry registry.Entry
	data  []byte
	reply chan signResult
}

type signResult struct {
	sig *ssh.Signature
	err error
}

var _ xagent.Agent = (*Agent)(nil)

// New returns an agent serving reg's keys. present performs the user-presence
// check (Touch ID); ttl is how long one check stays valid for a given key.
func New(reg *registry.Registry, signers SignerSource, present func(reason string) error, ttl time.Duration) *Agent {
	return &Agent{
		reg:     reg,
		signers: signers,
		present: present,
		ttl:     ttl,
		until:   map[string]time.Time{},
		jobs:    make(chan signJob),
	}
}

// Run performs signing — and its presence prompt — on the calling goroutine,
// which must be the main OS thread (runtime.LockOSThread) so macOS can draw the
// Touch ID prompt. It blocks for the process lifetime; the jobs channel is never
// closed.
func (a *Agent) Run() {
	for j := range a.jobs {
		j.reply <- a.signNow(j.entry, j.data)
	}
}

// signNow gates presence then signs. Runs on the main thread via Run.
func (a *Agent) signNow(e registry.Entry, data []byte) signResult {
	a.mu.Lock()
	fresh := time.Now().Before(a.until[e.Name])
	a.mu.Unlock()

	if !fresh {
		if err := a.present(fmt.Sprintf("authenticate to use sinete key %q", e.Name)); err != nil {
			return signResult{err: err}
		}
		a.mu.Lock()
		a.until[e.Name] = time.Now().Add(a.ttl)
		a.mu.Unlock()
	}

	signer, err := a.signers.Signer(e.Label, e.Tag)
	if err != nil {
		return signResult{err: err}
	}
	sig, err := signer.Sign(rand.Reader, data)
	return signResult{sig: sig, err: err}
}

// List advertises every key in the registry. It does not touch the secure
// element or prompt.
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

// Sign signs data with the registry key matching key, prompting for presence if
// that key's window has lapsed.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	e, ok := a.entryFor(key)
	if !ok {
		return nil, errNotFound
	}
	reply := make(chan signResult, 1)
	a.jobs <- signJob{entry: e, data: data, reply: reply}
	r := <-reply
	return r.sig, r.err
}

// entryFor returns the registry entry whose public key matches key.
func (a *Agent) entryFor(key ssh.PublicKey) (registry.Entry, bool) {
	want := key.Marshal()
	for _, e := range a.reg.List() {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
		if err != nil {
			continue
		}
		if bytes.Equal(pub.Marshal(), want) {
			return e, true
		}
	}
	return registry.Entry{}, false
}

// Remove forgets a key's presence window (ssh-add -d): the next use prompts
// again. It does not unadvertise or delete the key.
func (a *Agent) Remove(key ssh.PublicKey) error {
	if e, ok := a.entryFor(key); ok {
		a.mu.Lock()
		delete(a.until, e.Name)
		a.mu.Unlock()
	}
	return nil
}

// RemoveAll forgets every presence window (ssh-add -D): a "lock all".
func (a *Agent) RemoveAll() error {
	a.mu.Lock()
	a.until = map[string]time.Time{}
	a.mu.Unlock()
	return nil
}

// The remaining operations are unsupported (delegation will forward them later).
func (a *Agent) Add(xagent.AddedKey) error      { return errUnsupported }
func (a *Agent) Lock([]byte) error              { return errUnsupported }
func (a *Agent) Unlock([]byte) error            { return errUnsupported }
func (a *Agent) Signers() ([]ssh.Signer, error) { return nil, errUnsupported }
