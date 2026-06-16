// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paulofduarte/sinete/internal/registry"
	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

// fakeSource resolves labels to in-memory signers, standing in for the enclave.
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

func newReg(t *testing.T, entries ...registry.Entry) *registry.Registry {
	t.Helper()
	r, err := registry.Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		r.Add(e)
	}
	return r
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
	e := registry.Entry{Name: name, Label: "sinete-" + name, Tag: "dev.sinete", PublicKey: line}
	return e, pub, signer
}

func newAgent(t *testing.T, c *counter, ttl time.Duration, e registry.Entry, signer ssh.Signer) *Agent {
	t.Helper()
	return New(newReg(t, e), fakeSource{map[string]ssh.Signer{e.Label: signer}}, c.present, ttl)
}

func TestListAdvertisesRegistry(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	a := newAgent(t, &counter{}, time.Hour, e, signer)

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
	a := newAgent(t, c, time.Hour, e, signer)
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

func TestSignPromptsEverySignatureWhenTTLZero(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	c := &counter{}
	a := newAgent(t, c, 0, e, signer)
	go a.Run()

	for i := 0; i < 2; i++ {
		if _, err := a.Sign(pub, []byte("data")); err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
	}
	if got := c.count(); got != 2 {
		t.Fatalf("present called %d times, want 2 (TTL=0 ⇒ every signature)", got)
	}
}

func TestSignPresenceDenied(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	c := &counter{err: errors.New("denied")}
	a := newAgent(t, c, time.Hour, e, signer)
	go a.Run()

	if _, err := a.Sign(pub, []byte("data")); err == nil {
		t.Fatal("Sign should fail when presence is denied")
	}
}

func TestRemoveAllForgetsWindow(t *testing.T) {
	e, pub, signer := testEntry(t, "work")
	c := &counter{}
	a := newAgent(t, c, time.Hour, e, signer)
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

func TestSignNoMatch(t *testing.T) {
	e, _, signer := testEntry(t, "work")
	_, other, _ := testEntry(t, "other")
	a := newAgent(t, &counter{}, time.Hour, e, signer)

	if _, err := a.Sign(other, []byte("x")); err == nil {
		t.Fatal("Sign with an unknown key should error")
	}
}

func TestMutationsUnsupported(t *testing.T) {
	e, _, signer := testEntry(t, "work")
	a := newAgent(t, &counter{}, time.Hour, e, signer)
	if err := a.Lock(nil); err == nil {
		t.Error("Lock should be unsupported")
	}
	if err := a.Add(xagent.AddedKey{}); err == nil {
		t.Error("Add should be unsupported")
	}
}
