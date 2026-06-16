// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package agent implements sinete's ssh-agent (Model B).
//
// It advertises every key in the registry — so ssh/git use them with no manual
// step, like a normal agent — and enforces user presence at *sign* time. Each
// key has a presence window with two bounds (after gpg-agent): an idle TTL that
// resets on every signature, and an absolute cap from the first signature. The
// first signature with a key prompts for Touch ID; subsequent signatures are
// silent until the window lapses (idle elapsed, or the cap reached), after which
// the next signature prompts again. The keys are presence-less in the secure
// element; the agent holds only enclave-backed signer *handles*, never key
// material, and every signature is computed in hardware.
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

// Built-in presence TTLs, used when config leaves them unset. 10m/2h mirror
// gpg-agent's default-cache-ttl / max-cache-ttl.
const (
	DefaultIdleTTL = 10 * time.Minute
	DefaultMaxTTL  = 2 * time.Hour
)

var (
	errUnsupported = errors.New("sinete agent is read-only; manage keys with the sinete CLI")
	errNotFound    = errors.New("agent: no matching key")
)

// Store is the agent's live view of the keys it serves and their presence TTLs.
// It is re-read per operation so `sinete config` / `sinete generate` take effect
// without an agent restart.
type Store interface {
	Keys() ([]registry.Entry, error)
	// TTL returns the effective idle and absolute-cap durations for a key.
	TTL(name string) (idle, max time.Duration)
}

// SignerSource resolves an enclave key (by its sks label and tag) to a signer.
// Abstracted so the agent's presence/TTL logic is testable without hardware.
type SignerSource interface {
	Signer(label, tag string) (ssh.Signer, error)
}

// EnclaveSource is the production SignerSource, backed by the secure element.
type EnclaveSource struct{}

// Signer returns an enclave-backed ssh.Signer for the given label and tag.
func (EnclaveSource) Signer(label, tag string) (ssh.Signer, error) {
	return enclave.OpenLabelTag(label, tag).Signer()
}

// RegistryStore is the production Store: it re-opens the registry file on each
// call so key and config changes are picked up live. Built-in TTLs apply when a
// setting is unset or unparseable.
type RegistryStore struct{ Path string }

// Keys returns the registry's current entries.
func (s RegistryStore) Keys() ([]registry.Entry, error) {
	r, err := registry.Open(s.Path)
	if err != nil {
		return nil, err
	}
	return r.List(), nil
}

// TTL resolves the effective idle and absolute-cap durations for a key.
func (s RegistryStore) TTL(name string) (idle, max time.Duration) {
	idle, max = DefaultIdleTTL, DefaultMaxTTL
	r, err := registry.Open(s.Path)
	if err != nil {
		return idle, max
	}
	if d, ok := parseDur(r.Effective(name, registry.PresenceTTL)); ok {
		idle = d
	}
	if d, ok := parseDur(r.Effective(name, registry.PresenceMaxTTL)); ok {
		max = d
	}
	return idle, max
}

func parseDur(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false
	}
	return d, true
}

// window tracks a key's presence authentication: created at the prompt, accessed
// on each signature within it.
type window struct {
	created  time.Time
	accessed time.Time
}

// Agent serves a Store's keys over the ssh-agent protocol, gating presence at
// sign time. It satisfies golang.org/x/crypto/ssh/agent.Agent.
type Agent struct {
	store   Store
	signers SignerSource
	present func(reason string) error

	mu      sync.Mutex
	windows map[string]window
	jobs    chan signJob
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

// New returns an agent serving store's keys. present performs the user-presence
// check (Touch ID).
func New(store Store, signers SignerSource, present func(reason string) error) *Agent {
	return &Agent{
		store:   store,
		signers: signers,
		present: present,
		windows: map[string]window{},
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
	idle, max := a.store.TTL(e.Name)
	now := time.Now()

	a.mu.Lock()
	w, ok := a.windows[e.Name]
	fresh := ok && now.Before(w.accessed.Add(idle)) && now.Before(w.created.Add(max))
	a.mu.Unlock()

	if fresh {
		w.accessed = now // idle refresh
	} else {
		if err := a.present(fmt.Sprintf("authenticate to use sinete key %q", e.Name)); err != nil {
			return signResult{err: err}
		}
		now = time.Now()
		w = window{created: now, accessed: now}
	}

	a.mu.Lock()
	a.windows[e.Name] = w
	a.mu.Unlock()

	signer, err := a.signers.Signer(e.Label, e.Tag)
	if err != nil {
		return signResult{err: err}
	}
	sig, err := signer.Sign(rand.Reader, data)
	return signResult{sig: sig, err: err}
}

// List advertises every key the store reports. It does not prompt.
func (a *Agent) List() ([]*xagent.Key, error) {
	entries, err := a.store.Keys()
	if err != nil {
		return nil, err
	}
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

// Sign signs data with the key matching key, prompting for presence if that
// key's window has lapsed.
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

// entryFor returns the store entry whose public key matches key.
func (a *Agent) entryFor(key ssh.PublicKey) (registry.Entry, bool) {
	entries, err := a.store.Keys()
	if err != nil {
		return registry.Entry{}, false
	}
	want := key.Marshal()
	for _, e := range entries {
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
		delete(a.windows, e.Name)
		a.mu.Unlock()
	}
	return nil
}

// RemoveAll forgets every presence window (ssh-add -D): a "lock all".
func (a *Agent) RemoveAll() error {
	a.mu.Lock()
	a.windows = map[string]window{}
	a.mu.Unlock()
	return nil
}

// The remaining operations are unsupported (delegation will forward them later).
func (a *Agent) Add(xagent.AddedKey) error      { return errUnsupported }
func (a *Agent) Lock([]byte) error              { return errUnsupported }
func (a *Agent) Unlock([]byte) error            { return errUnsupported }
func (a *Agent) Signers() ([]ssh.Signer, error) { return nil, errUnsupported }
