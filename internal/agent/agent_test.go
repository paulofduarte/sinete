// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulofduarte/sinete/internal/registry"
	"golang.org/x/crypto/ssh"
)

func testPub(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub, string(ssh.MarshalAuthorizedKey(pub))
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

func TestListReportsRegistryKeys(t *testing.T) {
	pub, line := testPub(t)
	a := New(newReg(t, registry.Entry{Name: "work", PublicKey: line}))

	keys, err := a.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("List returned %d keys, want 1", len(keys))
	}
	if keys[0].Comment != "work" {
		t.Errorf("comment = %q, want work", keys[0].Comment)
	}
	if keys[0].Format != pub.Type() {
		t.Errorf("format = %q, want %q", keys[0].Format, pub.Type())
	}
}

func TestEntryForMatches(t *testing.T) {
	pub, line := testPub(t)
	other, _ := testPub(t)
	a := New(newReg(t, registry.Entry{Name: "work", PublicKey: line}))

	if e, ok := a.entryFor(pub); !ok || e.Name != "work" {
		t.Errorf("entryFor(known) = %q,%v; want work,true", e.Name, ok)
	}
	if _, ok := a.entryFor(other); ok {
		t.Error("entryFor(unknown) matched")
	}
}

// TestSignNoMatchDoesNotBlock guards the fast path: an unknown key must return
// an error immediately, before dispatching to Run (which isn't running here), so
// a missing key can never deadlock a caller.
func TestSignNoMatchDoesNotBlock(t *testing.T) {
	a := New(newReg(t)) // empty registry: nothing matches
	unknown, _ := testPub(t)

	done := make(chan error, 1)
	go func() {
		_, err := a.Sign(unknown, []byte("data"))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Sign with no matching key should return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sign blocked on the Run loop for an unknown key; want an immediate error")
	}
}

func TestMutationsUnsupported(t *testing.T) {
	a := New(newReg(t))
	if err := a.RemoveAll(); err == nil {
		t.Error("RemoveAll should be unsupported")
	}
	if err := a.Lock(nil); err == nil {
		t.Error("Lock should be unsupported")
	}
}
