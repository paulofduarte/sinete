// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paulofduarte/sinete/internal/registry"
	"golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

// Keys come from secure-element enumeration (which needs the entitled bundle), so
// the success path is exercised on-device via `sinete _enclave-check` and manual
// `ssh-setup`. Here we cover the error paths: an invalid name is rejected before
// any keychain access, and a valid name with no usable key — enumeration errors
// or finds no match for an unentitled test process — yields an error rather than
// writing a file.
func TestSshSetupErrors(t *testing.T) {
	out := filepath.Join(t.TempDir(), "k.pub")

	if err := cmdSshSetup([]string{"--out", out, "../evil"}); err == nil {
		t.Error("ssh-setup should reject an invalid key name")
	}
	if err := cmdSshSetup([]string{"--out", out, "work"}); err == nil {
		t.Error("ssh-setup on an unknown key should error")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("ssh-setup wrote %s for a key that does not exist", out)
	}
}

func TestSameSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A symlink to our socket must be recognised as the same file: a string
	// compare would miss it and the agent would delegate to itself.
	link := filepath.Join(dir, "agent-link.sock")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}

	if !sameSocket(sock, sock) {
		t.Error("identical paths should match")
	}
	if !sameSocket(sock, link) {
		t.Error("a symlink to the socket should match (self-delegation guard)")
	}

	other := filepath.Join(dir, "other.sock")
	ln2, err := net.Listen("unix", other)
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	if sameSocket(sock, other) {
		t.Error("distinct sockets should not match")
	}
	if sameSocket(sock, filepath.Join(dir, "nope.sock")) {
		t.Error("a nonexistent path should not match")
	}
}

// recordingAgent is a stub presenceDenyingAgent that records which presence-denying
// sign variant the wrapper routed to. The nil embedded interface supplies the other
// methods (unused by the test). The refuse-vs-delegate decision itself is tested
// authoritatively in internal/agent (TestSignDenyingPresence); here we only assert
// the wrapper routes signing through the *DenyingPresence path rather than the
// prompting one.
type recordingAgent struct {
	xagent.ExtendedAgent
	denied, deniedFlags bool
}

func (r *recordingAgent) SignDenyingPresence(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	r.denied = true
	return &ssh.Signature{}, nil
}

func (r *recordingAgent) SignWithFlagsDenyingPresence(ssh.PublicKey, []byte, xagent.SignatureFlags) (*ssh.Signature, error) {
	r.deniedFlags = true
	return &ssh.Signature{}, nil
}

func testPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestRemoteRefusingAgent(t *testing.T) {
	stub := &recordingAgent{}
	r := remoteRefusingAgent{stub}

	if _, err := r.Sign(testPub(t), []byte("x")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !stub.denied {
		t.Error("Sign should route through SignDenyingPresence")
	}

	if _, err := r.SignWithFlags(testPub(t), []byte("x"), 0); err != nil {
		t.Fatalf("SignWithFlags: %v", err)
	}
	if !stub.deniedFlags {
		t.Error("SignWithFlags should route through SignWithFlagsDenyingPresence")
	}
}

func TestPopBoolFlag(t *testing.T) {
	// The flag is removed wherever it appears, even after positional verbs.
	got, found := popBoolFlag([]string{"set", "presence-max-ttl", "1h", "--yes"}, "--yes", "-y")
	if !found {
		t.Error("--yes should be found")
	}
	want := []string{"set", "presence-max-ttl", "1h"}
	if len(got) != len(want) {
		t.Fatalf("popBoolFlag = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("popBoolFlag[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if _, found := popBoolFlag([]string{"show"}, "--yes", "-y"); found {
		t.Error("--yes should not be found when absent")
	}
	// Every occurrence is removed, not just the first.
	if got, _ := popBoolFlag([]string{"-y", "set", "--yes"}, "--yes", "-y"); len(got) != 1 || got[0] != "set" {
		t.Errorf("popBoolFlag should strip all matches, got %v", got)
	}
}

func TestParseSetting(t *testing.T) {
	if d, err := parseSetting(registry.PresenceTTL, "10m"); err != nil || d != 10*time.Minute {
		t.Errorf("parseSetting(ttl, 10m) = %v, %v, want 10m, nil", d, err)
	}
	if _, err := parseSetting("bogus", "10m"); err == nil {
		t.Error("unknown setting should error")
	}
	if _, err := parseSetting(registry.PresenceTTL, "nope"); err == nil {
		t.Error("invalid duration should error")
	}
	if _, err := parseSetting(registry.PresenceTTL, "-5m"); err == nil {
		t.Error("a negative duration should error")
	}
}
