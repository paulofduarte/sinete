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
// Clients reach sinete by configuration — ssh_config IdentityAgent, or
// SSH_AUTH_SOCK for git signing — not by taking over the session's agent. To
// stay transparent, the agent delegates everything it doesn't own to the
// upstream agent it inherited via SSH_AUTH_SOCK (normally the system
// ssh-agent): List is the union, and Sign/Add/Remove/Lock/Unlock/Extension for
// non-enclave keys forward upstream. With no upstream it is enclave-only.
package agent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
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

	// ErrPresenceUnavailable is returned by the *DenyingPresence sign variants when
	// a caller that cannot satisfy a presence prompt (a remote/headless connection)
	// asks to sign one of this agent's presence-gated enclave keys. It is surfaced to
	// the ssh-agent client in place of hanging on an invisible Touch ID prompt.
	ErrPresenceUnavailable = errors.New("sinete: can't confirm user presence for this connection — it has no local interactive session (e.g. SSH); sign from the machine's console")
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

// EnclaveStore is the production Store. Keys are enumerated from the secure
// element — the source of truth for which keys exist — and TTLs come from the
// signed config registry. The config is re-verified only when registry.json
// changes (see config), so a `sinete config` write is picked up promptly without
// re-reading and re-verifying on every signature. A config that fails
// verification (for any reason) yields strict TTLs (0/0 — authenticate every
// signature): Effective returns "" when the store is untrusted, so this is the
// fail-CLOSED path — tampering can only tighten, never relax.
type EnclaveStore struct {
	mu    sync.Mutex
	cfg   *registry.Config
	stamp string // mtime:size of registry.json at last load ("absent" if missing)
}

// NewEnclaveStore returns the production Store.
func NewEnclaveStore() *EnclaveStore { return &EnclaveStore{} }

// Keys enumerates the secure element and presents each key as a registry.Entry
// (the on-the-fly index the agent's matching/signing logic expects).
func (s *EnclaveStore) Keys() ([]registry.Entry, error) {
	listed, err := enclave.List()
	if err != nil {
		return nil, err
	}
	out := make([]registry.Entry, 0, len(listed))
	for _, k := range listed {
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey))) + " " + k.Name
		out = append(out, registry.Entry{Name: k.Name, Label: k.Label, Tag: enclave.Tag, PublicKey: line})
	}
	return out, nil
}

// TTL resolves the effective idle and absolute-cap durations for a key from the
// (cached) signed config. The fail-closed fallback is 0/0 — authenticate on every
// signature — applied when a value is unset, unparseable, or the config is
// untrusted; only a configured, verified value relaxes from strict. (max == 0 or
// idle == 0 both force a prompt every signature, so an unset presence-max-ttl
// keeps a configured presence-ttl strict — the ceiling is enforced structurally.)
func (s *EnclaveStore) TTL(name string) (idle, max time.Duration) {
	cfg := s.config()
	if cfg == nil {
		return 0, 0
	}
	if d, ok := parseDur(cfg.Effective(name, registry.PresenceTTL)); ok {
		idle = d
	}
	if d, ok := parseDur(cfg.Effective(name, registry.PresenceMaxTTL)); ok {
		max = d
	}
	return idle, max
}

// config returns the verified signed config, reloading (and re-verifying) it only
// when registry.json's mtime/size changes. This keeps per-signature TTL lookups
// off the filesystem/keychain on the hot path while still picking up a
// `sinete config` write promptly — a write atomically replaces the file, changing
// its stamp. Tamper/replay is still caught: any on-disk change reloads and
// re-verifies (and the verify itself checks signature + keychain epoch).
func (s *EnclaveStore) config() *registry.Config {
	path, err := registry.ConfigPath()
	if err != nil {
		return nil
	}
	// Stat under the lock so the stamp and the cache decision are consistent: a
	// change between stat and check could otherwise return a stale config.
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp := "absent"
	if fi, serr := os.Stat(path); serr == nil {
		stamp = fmt.Sprintf("%d:%d", fi.ModTime().UnixNano(), fi.Size())
	}
	if s.cfg != nil && s.stamp == stamp {
		return s.cfg
	}
	cfg, _, err := registry.OpenConfig(path, enclave.ConfigCrypto{})
	if err != nil {
		return nil
	}
	s.cfg, s.stamp = cfg, stamp
	return cfg
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

	signer, err := a.signers.Signer(e.Label, e.Tag)
	if err != nil {
		return signResult{err: err}
	}
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return signResult{err: err}
	}

	// Open/refresh the presence window only after a signature actually succeeds,
	// so a failed signer lookup or sign doesn't let the next attempt skip the
	// prompt. And only if no Remove/RemoveAll ran while we prompted/signed
	// (ssh-add -d/-D): otherwise we'd resurrect a window the user just cleared.
	a.mu.Lock()
	if a.gen == gen {
		a.windows[keyID] = w
	}
	a.mu.Unlock()

	return signResult{sig: sig}
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
		// List is the union; surface an upstream failure rather than silently
		// returning a partial list (which would hide non-enclave keys from
		// ssh-add -l with no error), consistent with how Sign forwards upstream.
		up, err := a.upstream.List()
		if err != nil {
			return nil, fmt.Errorf("upstream agent list: %w", err)
		}
		keys = append(keys, up...)
	}
	return keys, nil
}

// Sign signs with an enclave key (prompting for presence as needed) or forwards
// to the upstream agent.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.signRouted(key, data, 0, false, false)
}

// SignWithFlags is like Sign but honours the rsa-sha2 flags for upstream keys
// (enclave keys are ECDSA, so the flags do not apply to them).
func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags xagent.SignatureFlags) (*ssh.Signature, error) {
	return a.signRouted(key, data, flags, true, false)
}

// SignDenyingPresence is Sign for a caller that cannot satisfy a presence prompt
// (a remote/headless connection): an enclave key it owns is refused with
// ErrPresenceUnavailable instead of dispatching a Touch ID prompt that would hang,
// while upstream-delegated keys forward unchanged. See signRouted — there is a
// single, authoritative ownership lookup, so no second check can diverge and
// re-introduce the prompt this is meant to prevent.
func (a *Agent) SignDenyingPresence(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.signRouted(key, data, 0, false, true)
}

// SignWithFlagsDenyingPresence is SignWithFlags for a presence-unavailable caller;
// see SignDenyingPresence.
func (a *Agent) SignWithFlagsDenyingPresence(key ssh.PublicKey, data []byte, flags xagent.SignatureFlags) (*ssh.Signature, error) {
	return a.signRouted(key, data, flags, true, true)
}

// signRouted resolves key once and routes it: an enclave key is either gated and
// signed, or — when denyPresence is set for a caller that can't prompt — refused
// with ErrPresenceUnavailable; any other key forwards to upstream (honouring flags
// when useFlags is set). The single entryFor lookup is deliberate: a remote-refusal
// wrapper must not run its own ownership check and then delegate here, since the two
// checks could disagree (a transient store error, or a key added/removed in between)
// and let an enclave key slip into a presence prompt. A lookup error is surfaced,
// never treated as "not owned" — fail-closed, so an unreadable key index can't cause
// an owned key to be delegated (and possibly prompted) instead of refused.
func (a *Agent) signRouted(key ssh.PublicKey, data []byte, flags xagent.SignatureFlags, useFlags, denyPresence bool) (*ssh.Signature, error) {
	e, ok, err := a.entryFor(key)
	if err != nil {
		return nil, err
	}
	if ok {
		if denyPresence {
			return nil, ErrPresenceUnavailable
		}
		return a.signEnclave(e, string(key.Marshal()), data)
	}
	if a.upstream == nil {
		return nil, errNotFound
	}
	if useFlags {
		return a.upstream.SignWithFlags(key, data, flags)
	}
	return a.upstream.Sign(key, data)
}

// entryFor returns the store entry whose public key matches key. A non-nil error
// means the key index could not be read -- callers surface it rather than treat
// the key as absent, so a registry failure doesn't masquerade as "no such key"
// (or get silently forwarded upstream).
func (a *Agent) entryFor(key ssh.PublicKey) (registry.Entry, bool, error) {
	entries, err := a.store.Keys()
	if err != nil {
		return registry.Entry{}, false, err
	}
	want := key.Marshal()
	for _, e := range entries {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
		if err != nil {
			continue
		}
		if bytes.Equal(pub.Marshal(), want) {
			return e, true, nil
		}
	}
	return registry.Entry{}, false, nil
}

// Remove forgets an enclave key's presence window (ssh-add -d: the next use
// prompts again; it does not delete the key) or forwards to the upstream agent.
func (a *Agent) Remove(key ssh.PublicKey) error {
	_, ok, err := a.entryFor(key)
	if err != nil {
		return err
	}
	if ok {
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
