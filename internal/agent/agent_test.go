package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"testing"

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
	a := New("sinete", newReg(t, registry.Entry{Name: "work", PublicKey: line}))

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

func TestNameForMatches(t *testing.T) {
	pub, line := testPub(t)
	other, _ := testPub(t)
	a := New("sinete", newReg(t, registry.Entry{Name: "work", PublicKey: line}))

	if name, ok := a.nameFor(pub); !ok || name != "work" {
		t.Errorf("nameFor(known) = %q,%v; want work,true", name, ok)
	}
	if _, ok := a.nameFor(other); ok {
		t.Error("nameFor(unknown) matched")
	}
}

func TestMutationsUnsupported(t *testing.T) {
	a := New("sinete", newReg(t))
	if err := a.RemoveAll(); err == nil {
		t.Error("RemoveAll should be unsupported")
	}
	if err := a.Lock(nil); err == nil {
		t.Error("Lock should be unsupported")
	}
}
