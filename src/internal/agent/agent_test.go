// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulofduarte/sinete/internal/registry"
	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

// fakeStore serves fixed entries and TTLs, standing in for the registry.
type fakeStore struct {
	entries   []registry.Entry
	idle, max time.Duration
}

func (s fakeStore) Keys() ([]registry.Entry, error)      { return s.entries, nil }
func (s fakeStore) TTL(string) (idle, max time.Duration) { return s.idle, s.max }

// mutableStore lets a test change the served entries after the agent is built.
type mutableStore struct {
	mu        sync.Mutex
	entries   []registry.Entry
	idle, max time.Duration
}

func (s *mutableStore) Keys() ([]registry.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries, nil
}

func (s *mutableStore) TTL(string) (idle, max time.Duration) { return s.idle, s.max }

func (s *mutableStore) set(entries ...registry.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = entries
}

// fakeSource resolves labels to in-memory signers, standing in for the cryptoprocessor.
type fakeSource struct{ signers map[string]ssh.Signer }

func (f fakeSource) Signer(label, _ string) (ssh.Signer, error) {
	s, ok := f.signers[label]
	if !ok {
		return nil, fmt.Errorf("no signer for %q", label)
	}
	return s, nil
}

// counter is a presence func that counts calls and can be made to fail.
type counter struct {
	mu  sync.Mutex
	n   int
	err error
}

func (c *counter) present(string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.err
}

func (c *counter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func testEntry(t *testing.T, name string) (registry.Entry, ssh.PublicKey, ssh.Signer) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + name
	e := registry.Entry{Name: name, Label: "sinete-" + name, Tag: "me.paulofduarte.sinete", PublicKey: line}
	return e, pub, signer
}

func newAgent(t *testing.T, c *counter, idle, max time.Duration, e registry.Entry, signer ssh.Signer) *Agent {
	t.Helper()
	store := fakeStore{entries: []registry.Entry{e}, idle: idle, max: max}
	return New(store, fakeSource{map[string]ssh.Signer{e.Label: signer}}, c.present, nil)
}

func TestListAdvertisesStore(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	a := newAgent(t, &counter{}, time.Hour, time.Hour, e, signer)

	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Comment != "work" {
		t.Fatalf("List = %+v, want one comment=work", keys)
	}
	if keys[0].Format != pub.Type() {
		t.Errorf("format = %q, want %q", keys[0].Format, pub.Type())
	}
}

func TestSignPromptsThenCaches(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	c := &counter{}
	a := newAgent(t, c, time.Hour, time.Hour, e, signer)
	go a.Run()

	for i := 0; i < 2; i++ {
		sig, err := a.Sign(pub, []byte("data"))
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		if err := pub.Verify([]byte("data"), sig); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if got := c.count(); got != 1 {
		t.Fatalf("present called %d times, want 1 (second signature cached)", got)
	}
}

func TestSignPromptsEverySignatureWhenIdleZero(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	c := &counter{}
	a := newAgent(t, c, 0, time.Hour, e, signer)
	go a.Run()

	for i := 0; i < 2; i++ {
		if _, err := a.Sign(pub, []byte("data")); err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
	}
	if got := c.count(); got != 2 {
		t.Fatalf("present called %d times, want 2 (idle=0 ⇒ every signature)", got)
	}
}

func TestAbsoluteCapForcesReprompt(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	c := &counter{}
	// Large idle, zero cap: the absolute cap is exceeded immediately, so even a
	// back-to-back signature must re-prompt.
	a := newAgent(t, c, time.Hour, 0, e, signer)
	go a.Run()

	for i := 0; i < 2; i++ {
		if _, err := a.Sign(pub, []byte("data")); err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
	}
	if got := c.count(); got != 2 {
		t.Fatalf("present called %d times, want 2 (max cap forces re-prompt)", got)
	}
}

func TestSignPresenceDenied(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	c := &counter{err: errors.New("denied")}
	a := newAgent(t, c, time.Hour, time.Hour, e, signer)
	go a.Run()

	if _, err := a.Sign(pub, []byte("data")); err == nil {
		t.Fatal("Sign should fail when presence is denied")
	}
}

// A failed signature must not open the presence window: the user authenticated
// but no signature was produced, so the next attempt has to prompt again.
func TestFailedSignDoesNotCachePresence(t *testing.T) {
	e, pub, _ := testEntry(t, "work")
	c := &counter{}
	store := fakeStore{entries: []registry.Entry{e}, idle: time.Hour, max: time.Hour}
	// No signer for this label, so Signer() fails after the presence prompt.
	a := New(store, fakeSource{map[string]ssh.Signer{}}, c.present, nil)
	go a.Run()

	for i := 0; i < 2; i++ {
		if _, err := a.Sign(pub, []byte("data")); err == nil {
			t.Fatalf("sign %d: expected failure when the signer is unavailable", i)
		}
	}
	if got := c.count(); got != 2 {
		t.Fatalf("present called %d times, want 2 (a failed signature must not open the window)", got)
	}
}

func TestRemoveAllForgetsWindow(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	c := &counter{}
	a := newAgent(t, c, time.Hour, time.Hour, e, signer)
	go a.Run()

	if _, err := a.Sign(pub, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := a.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Sign(pub, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if got := c.count(); got != 2 {
		t.Fatalf("present called %d times, want 2 (RemoveAll re-locks)", got)
	}
}

func TestRecreatedKeyReprompts(t *testing.T) {
	e1, pub1, signer := testEntry(t, "work")
	e2, pub2, _ := testEntry(t, "work") // same name, new key material
	c := &counter{}
	store := &mutableStore{entries: []registry.Entry{e1}, idle: time.Hour, max: time.Hour}
	a := New(store, fakeSource{map[string]ssh.Signer{e1.Label: signer}}, c.present, nil)
	go a.Run()

	if _, err := a.Sign(pub1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	store.set(e2) // the key was deleted and recreated under the same name

	if _, err := a.Sign(pub2, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := c.count(); got != 2 {
		t.Fatalf("present called %d times, want 2 (recreated key must re-authenticate)", got)
	}
}

func TestSignNoMatch(t *testing.T) {
	e, _, signer := testEntry(t, "work")
	_, other, _ := testEntry(t, "other")
	a := newAgent(t, &counter{}, time.Hour, time.Hour, e, signer)

	if _, err := a.Sign(other, []byte("x")); err == nil {
		t.Fatal("Sign with an unknown key should error")
	}
}

// erroringUpstream is an upstream whose List always fails, to check that the
// agent surfaces the error instead of silently dropping upstream keys.
type erroringUpstream struct{ xagent.ExtendedAgent }

func (erroringUpstream) List() ([]*xagent.Key, error) {
	return nil, errors.New("upstream unavailable")
}

func TestListPropagatesUpstreamError(t *testing.T) {
	e, _, signer := testEntry(t, "work")
	store := fakeStore{entries: []registry.Entry{e}, idle: time.Hour, max: time.Hour}
	up := erroringUpstream{xagent.NewKeyring().(xagent.ExtendedAgent)}
	a := New(store, fakeSource{map[string]ssh.Signer{e.Label: signer}}, (&counter{}).present, up)

	if _, err := a.List(); err == nil {
		t.Fatal("List should propagate the upstream agent's error, not drop its keys")
	}
}

func TestDelegatesToUpstream(t *testing.T) {
	e, _, signer := testEntry(t, "work")

	// Upstream agent (a plain in-memory keyring) holding its own key.
	up := xagent.NewKeyring()
	upPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Add(xagent.AddedKey{PrivateKey: upPriv}); err != nil {
		t.Fatal(err)
	}
	upPub, err := ssh.NewPublicKey(&upPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	c := &counter{}
	store := fakeStore{entries: []registry.Entry{e}, idle: time.Hour, max: time.Hour}
	a := New(store, fakeSource{map[string]ssh.Signer{e.Label: signer}}, c.present, up.(xagent.ExtendedAgent))
	go a.Run()

	// List is the union: enclave key + upstream key.
	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("List = %d keys, want 2 (enclave + upstream)", len(keys))
	}

	// Signing an upstream key forwards (no presence prompt) and verifies.
	sig, err := a.Sign(upPub, []byte("data"))
	if err != nil {
		t.Fatalf("sign upstream key: %v", err)
	}
	if err := upPub.Verify([]byte("data"), sig); err != nil {
		t.Fatalf("upstream signature does not verify: %v", err)
	}
	if got := c.count(); got != 0 {
		t.Errorf("present called %d times for an upstream key, want 0", got)
	}
}

// errStore fails every Keys() read, to exercise the fail-closed path.
type errStore struct{}

func (errStore) Keys() ([]registry.Entry, error)      { return nil, errors.New("store unavailable") }
func (errStore) TTL(string) (idle, max time.Duration) { return 0, 0 }

func TestSignDenyingPresence(t *testing.T) {
	// An owned (enclave) key is refused with ErrPresenceUnavailable and never
	// prompts or signs — the prompt is exactly what a remote/headless peer can't
	// satisfy.
	e, pub, signer := testEntry(t, "work")
	c := &counter{}
	a := newAgent(t, c, time.Hour, time.Hour, e, signer)
	go a.Run()

	if _, err := a.SignDenyingPresence(pub, []byte("x")); !errors.Is(err, ErrPresenceUnavailable) {
		t.Errorf("owned key: err = %v, want ErrPresenceUnavailable", err)
	}
	if _, err := a.SignWithFlagsDenyingPresence(pub, []byte("x"), 0); !errors.Is(err, ErrPresenceUnavailable) {
		t.Errorf("owned key (flags): err = %v, want ErrPresenceUnavailable", err)
	}
	if got := c.count(); got != 0 {
		t.Errorf("present called %d times for a refused key, want 0 (no prompt)", got)
	}

	// An upstream-delegated key still forwards and signs, with no prompt.
	up := xagent.NewKeyring()
	upPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Add(xagent.AddedKey{PrivateKey: upPriv}); err != nil {
		t.Fatal(err)
	}
	upPub, err := ssh.NewPublicKey(&upPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	store := fakeStore{entries: []registry.Entry{e}, idle: time.Hour, max: time.Hour}
	a2 := New(store, fakeSource{map[string]ssh.Signer{e.Label: signer}}, c.present, up.(xagent.ExtendedAgent))
	sig, err := a2.SignDenyingPresence(upPub, []byte("data"))
	if err != nil {
		t.Fatalf("upstream key should delegate, got %v", err)
	}
	if err := upPub.Verify([]byte("data"), sig); err != nil {
		t.Fatalf("delegated signature does not verify: %v", err)
	}

	// A store read error is surfaced (fail-closed), not swallowed into a delegate
	// or a "not owned" — an unreadable index must not let an owned key slip past.
	a3 := New(errStore{}, fakeSource{nil}, c.present, nil)
	if _, err := a3.SignDenyingPresence(pub, []byte("x")); err == nil || errors.Is(err, ErrPresenceUnavailable) {
		t.Errorf("store error: err = %v, want the underlying read error", err)
	}
}

func TestMutationsUnsupported(t *testing.T) {
	e, _, signer := testEntry(t, "work")
	a := newAgent(t, &counter{}, time.Hour, time.Hour, e, signer)
	if err := a.Lock(nil); err == nil {
		t.Error("Lock should be unsupported")
	}
	if err := a.Add(xagent.AddedKey{}); err == nil {
		t.Error("Add should be unsupported")
	}
}
