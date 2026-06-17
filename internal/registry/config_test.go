// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fakeCrypto stands in for the master key + epoch item: Sign is a deterministic
// tag over the payload, Verify recomputes it, and the epoch lives in a field.
// Tampering with the payload makes Verify fail; advancing the epoch behind an
// on-disk file makes that file stale.
type fakeCrypto struct{ epoch uint64 }

func (f *fakeCrypto) tag(payload []byte) []byte {
	h := sha256.Sum256(append([]byte("test-secret\x00"), payload...))
	return h[:]
}
func (f *fakeCrypto) Sign(payload []byte) ([]byte, error) { return f.tag(payload), nil }
func (f *fakeCrypto) Verify(payload, sig []byte) bool     { return bytes.Equal(f.tag(payload), sig) }
func (f *fakeCrypto) Epoch() (uint64, error)              { return f.epoch, nil }
func (f *fakeCrypto) SetEpoch(v uint64) error             { f.epoch = v; return nil }

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{}

	c, trusted, err := OpenConfig(path, fc)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Fatal("an absent config file should be trusted (defaults)")
	}
	if got := c.Effective("work", PresenceTTL); got != "" {
		t.Fatalf("empty store Effective = %q, want \"\"", got)
	}

	c.SetDefault(PresenceTTL, "10m")
	c.SetKeyConfig("work", PresenceTTL, "5m")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if fc.epoch != 1 {
		t.Fatalf("epoch after first save = %d, want 1", fc.epoch)
	}

	c2, trusted, err := OpenConfig(path, fc)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Fatal("freshly written config should be trusted")
	}
	if got := c2.Effective("work", PresenceTTL); got != "5m" {
		t.Fatalf("per-key override = %q, want 5m", got)
	}
	if got := c2.Effective("other", PresenceTTL); got != "10m" {
		t.Fatalf("fallback to default = %q, want 10m", got)
	}
	if got := c2.Effective("work", PresenceMaxTTL); got != "" {
		t.Fatalf("unset setting = %q, want \"\"", got)
	}
}

func TestConfigTamperFallsBackToDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{}

	c, _, _ := OpenConfig(path, fc)
	c.SetDefault(PresenceTTL, "10m")
	c.SetKeyConfig("work", PresenceTTL, "24h")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the signed payload so the signature no longer matches.
	data, _ := os.ReadFile(path)
	var env cfgEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload[len(env.Payload)/2] ^= 0xff
	out, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	c2, trusted, err := OpenConfig(path, fc)
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Fatal("tampered config must not be trusted")
	}
	if got := c2.Effective("work", PresenceTTL); got != "" {
		t.Fatalf("tampered config Effective = %q, want built-in default (\"\")", got)
	}
}

func TestConfigReplayRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{}

	c, _, _ := OpenConfig(path, fc)
	c.SetKeyConfig("work", PresenceTTL, "24h")
	if err := c.Save(); err != nil { // epoch 1
		t.Fatal(err)
	}
	old, _ := os.ReadFile(path) // a validly-signed epoch-1 revision

	c.SetKeyConfig("work", PresenceTTL, "5m")
	if err := c.Save(); err != nil { // epoch 2
		t.Fatal(err)
	}

	// Replay the old revision: its signature is valid but its epoch is stale.
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	c2, trusted, err := OpenConfig(path, fc)
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Fatal("a replayed (stale-epoch) config must not be trusted")
	}
	if got := c2.Effective("work", PresenceTTL); got != "" {
		t.Fatalf("replayed config Effective = %q, want built-in default (\"\")", got)
	}
}

func TestConfigRemoveKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{}

	c, _, _ := OpenConfig(path, fc)
	c.SetDefault(PresenceTTL, "10m")
	c.SetKeyConfig("work", PresenceTTL, "5m")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	c.RemoveKey("work")
	if c.HasKey("work") {
		t.Fatal("HasKey true after RemoveKey")
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	c2, trusted, err := OpenConfig(path, fc)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Fatal("config should be trusted")
	}
	if got := c2.Effective("work", PresenceTTL); got != "10m" {
		t.Fatalf("after RemoveKey, Effective = %q, want default 10m", got)
	}
}
