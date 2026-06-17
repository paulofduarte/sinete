// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package agent implements sinete's ssh-agent (Model B), a superset agent.
//
// It advertises every key in the registry — so ssh/git use them with no manual
// step, like a normal agent — and enforces user presence at *sign* time. Each
// key has a presence window with two bounds (after gpg-agent): an idle TTL that
// resets on every signature, and an absolute cap from the first signature. The
// first signature with a key prompts for Touch ID; subsequent signatures are
// silent until the window lapses, after which the next one prompts again. The
// keys are presence-less in the secure element; the agent holds only enclave-
// backed signer *handles*, never key material, and every signature is computed
// in hardware.
//
// To stay transparent when it takes over SSH_AUTH_SOCK, the agent delegates
// everything it doesn't own to an upstream agent (e.g. the system ssh-agent):
// List is the union, and Sign/Add/Remove/Lock/Unlock/Extension for non-enclave
// keys forward upstream. With no upstream it is enclave-only.
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
// sign time, and delegates everything else to upstream (may be nil). It
// satisfies golang.org/x/crypto/ssh/agent.ExtendedAgent.
type Agent struct {
	store    Store
	signers  SignerSource
	present  func(reason string) error
	upstream xagent.ExtendedAgent

	mu      sync.Mutex
	windows map[string]window // keyed by the key's wire blob, not its name
	gen     uint64            // bumped by Remove/RemoveAll; see signNow's write-back
	jobs    chan signJob
}

type signJob struct {
	entry registry.Entry
	keyID string // the key's wire blob: presence windows are keyed by it, not the name
	data  []byte
	reply chan signResult
}

type signResult struct {
	sig *ssh.Signature
	err error
}

var _ xagent.ExtendedAgent = (*Agent)(nil)

// New returns an agent serving store's keys. present performs the user-presence
// check (Touch ID). upstream, if non-nil, receives every request for a key the
// agent does not own.
func New(store Store, signers SignerSource, present func(reason string) error, upstream xagent.ExtendedAgent) *Agent {
	return &Agent{
		store:    store,
		signers:  signers,
		present:  present,
		upstream: upstream,
		windows:  map[string]window{},
		jobs:     make(chan signJob),
	}
}

// Run performs enclave signing — and its presence prompt — on the calling
// goroutine, which must be the main OS thread (runtime.LockOSThread) so macOS
// can draw the Touch ID prompt. It blocks for the process lifetime.
func (a *Agent) Run() {
	for j := range a.jobs {
		j.reply <- a.signNow(j.entry, j.keyID, j.data)
	}
}

// signNow gates presence then signs an enclave key. Runs on the main thread. The
// presence window is keyed by keyID (the public key) rather than the name, so a
// deleted-and-recreated key — different key material under the same name — does
// not inherit the old key's window and must re-authenticate.
func (a *Agent) signNow(e registry.Entry, keyID string, data []byte) signResult {
	idle, max := a.store.TTL(e.Name)
	now := time.Now()

	a.mu.Lock()
	w, ok := a.windows[keyID]
	gen := a.gen
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

	// Record the window only if no Remove/RemoveAll ran while we were prompting
	// (ssh-add -d/-D): otherwise we'd resurrect a window the user just cleared.
	a.mu.Lock()
	if a.gen == gen {
		a.windows[keyID] = w
	}
	a.mu.Unlock()

	signer, err := a.signers.Signer(e.Label, e.Tag)
	if err != nil {
		return signResult{err: err}
	}
	sig, err := signer.Sign(rand.Reader, data)
	return signResult{sig: sig, err: err}
}

// signEnclave dispatches an enclave signature to the main-thread Run. keyID is
// the key's wire blob, used to key the presence window.
func (a *Agent) signEnclave(e registry.Entry, keyID string, data []byte) (*ssh.Signature, error) {
	reply := make(chan signResult, 1)
	a.jobs <- signJob{entry: e, keyID: keyID, data: data, reply: reply}
	r := <-reply
	return r.sig, r.err
}

// List advertises every enclave key plus, if delegating, the upstream agent's.
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
	if a.upstream != nil {
		if up, err := a.upstream.List(); err == nil {
			keys = append(keys, up...)
		}
	}
	return keys, nil
}

// Sign signs with an enclave key (prompting for presence as needed) or forwards
// to the upstream agent.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if e, ok := a.entryFor(key); ok {
		return a.signEnclave(e, string(key.Marshal()), data)
	}
	if a.upstream != nil {
		return a.upstream.Sign(key, data)
	}
	return nil, errNotFound
}

// SignWithFlags is like Sign but honours the rsa-sha2 flags for upstream keys
// (enclave keys are ECDSA, so the flags do not apply to them).
func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags xagent.SignatureFlags) (*ssh.Signature, error) {
	if e, ok := a.entryFor(key); ok {
		return a.signEnclave(e, string(key.Marshal()), data)
	}
	if a.upstream != nil {
		return a.upstream.SignWithFlags(key, data, flags)
	}
	return nil, errNotFound
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

// Remove forgets an enclave key's presence window (ssh-add -d: the next use
// prompts again; it does not delete the key) or forwards to the upstream agent.
func (a *Agent) Remove(key ssh.PublicKey) error {
	if _, ok := a.entryFor(key); ok {
		a.mu.Lock()
		delete(a.windows, string(key.Marshal()))
		a.gen++
		a.mu.Unlock()
		return nil
	}
	if a.upstream != nil {
		return a.upstream.Remove(key)
	}
	// Unknown key with no upstream: report failure (ssh-add -d of a key we don't
	// have should not look like success).
	return errNotFound
}

// RemoveAll forgets every enclave presence window and clears the upstream agent
// (ssh-add -D).
func (a *Agent) RemoveAll() error {
	a.mu.Lock()
	a.windows = map[string]window{}
	a.gen++
	a.mu.Unlock()
	if a.upstream != nil {
		return a.upstream.RemoveAll()
	}
	return nil
}

// Add, Lock, Unlock, Signers and Extension are not meaningful for enclave keys
// (managed by the sinete CLI); they forward to the upstream agent when present.
func (a *Agent) Add(key xagent.AddedKey) error {
	if a.upstream != nil {
		return a.upstream.Add(key)
	}
	return errUnsupported
}

func (a *Agent) Lock(passphrase []byte) error {
	if a.upstream != nil {
		return a.upstream.Lock(passphrase)
	}
	return errUnsupported
}

func (a *Agent) Unlock(passphrase []byte) error {
	if a.upstream != nil {
		return a.upstream.Unlock(passphrase)
	}
	return errUnsupported
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	if a.upstream != nil {
		return a.upstream.Signers()
	}
	return nil, errUnsupported
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if a.upstream != nil {
		return a.upstream.Extension(extensionType, contents)
	}
	return nil, xagent.ErrExtensionUnsupported
}
