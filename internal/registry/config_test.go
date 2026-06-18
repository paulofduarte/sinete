// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeCrypto stands in for the master key + epoch item: Sign is a deterministic
// tag over the payload, Verify recomputes it, and the epoch lives in a field.
// Tampering with the payload makes Verify fail; advancing the epoch behind an
// on-disk file makes that file stale.
type fakeCrypto struct {
	epoch       uint64
	setEpochErr error
}

func (f *fakeCrypto) tag(payload []byte) []byte {
	h := sha256.Sum256(append([]byte("test-secret\x00"), payload...))
	return h[:]
}
func (f *fakeCrypto) Sign(payload []byte) ([]byte, error) { return f.tag(payload), nil }
func (f *fakeCrypto) Verify(payload, sig []byte) bool     { return bytes.Equal(f.tag(payload), sig) }
func (f *fakeCrypto) Epoch() (uint64, error)              { return f.epoch, nil }
func (f *fakeCrypto) SetEpoch(v uint64) error {
	if f.setEpochErr != nil {
		return f.setEpochErr
	}
	f.epoch = v
	return nil
}

func TestConfigSaveEpochFailureUntrusted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{setEpochErr: errors.New("epoch write failed")}

	c, _, _ := OpenConfig(path, fc)
	c.SetDefault(PresenceTTL, "5m")
	if err := c.Save(); err == nil {
		t.Fatal("Save should fail when advancing the epoch fails")
	}
	if c.Trusted() {
		t.Error("Config should be untrusted after a failed epoch advance")
	}
	if got := c.Effective("x", PresenceTTL); got != "" {
		t.Errorf("untrusted Effective = %q, want strict fallback (\"\")", got)
	}
}

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{}

	c, trusted, err := OpenConfig(path, fc)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Fatal("an absent config file should be trusted (strict until configured)")
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

func TestConfigTamperFallsClosedToStrict(t *testing.T) {
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
		t.Fatalf("tampered config Effective = %q, want strict fallback (\"\")", got)
	}
}

func TestConfigUnknownVersionUntrusted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{}

	c, _, _ := OpenConfig(path, fc)
	c.SetKeyConfig("work", PresenceTTL, "5m")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	// Bump the envelope version (outside the signed payload, so the signature is
	// still valid). An unrecognised version must not be trusted.
	data, _ := os.ReadFile(path)
	var env cfgEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.V = 99
	out, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	c2, trusted, err := OpenConfig(path, fc)
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Fatal("config with an unknown envelope version must not be trusted")
	}
	if got := c2.Effective("work", PresenceTTL); got != "" {
		t.Fatalf("unknown-version config Effective = %q, want strict fallback (\"\")", got)
	}
}

func TestConfigUnreadableUntrusted(t *testing.T) {
	// A directory at the config path makes os.ReadFile fail with a non-NotExist
	// error; OpenConfig should treat that fail-safe (untrusted), not hard-error.
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	c, trusted, err := OpenConfig(path, &fakeCrypto{})
	if err != nil {
		t.Fatalf("OpenConfig should not hard-error on an unreadable file: %v", err)
	}
	if trusted {
		t.Error("an unreadable config must be untrusted")
	}
	if got := c.Effective("x", PresenceTTL); got != "" {
		t.Errorf("untrusted Effective = %q, want strict fallback (\"\")", got)
	}
}

func TestConfigEpochOverflowRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{epoch: math.MaxUint64}

	c, _, _ := OpenConfig(path, fc)
	c.SetDefault(PresenceTTL, "5m")
	if err := c.Save(); err == nil {
		t.Fatal("Save should refuse when the epoch would overflow to 0")
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
		t.Fatalf("replayed config Effective = %q, want strict fallback (\"\")", got)
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

// presence-max-ttl is global-only: SetKeyConfig refuses to store it per-key, so it
// never persists and Effective always reports the global value for the ceiling.
func TestConfigMaxTTLGlobalOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{}

	c, _, _ := OpenConfig(path, fc)
	c.SetDefault(PresenceMaxTTL, "2h")
	c.SetKeyConfig("work", PresenceMaxTTL, "24h") // ignored — not stored per-key
	c.SetKeyConfig("work", PresenceTTL, "30m")
	if got := c.KeyConfig("work")[PresenceMaxTTL]; got != "" {
		t.Errorf("per-key max-ttl stored = %q, want it ignored (\"\")", got)
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	c2, _, _ := OpenConfig(path, fc)
	if got := c2.Effective("work", PresenceMaxTTL); got != "2h" {
		t.Errorf("per-key max-ttl honoured = %q, want the global 2h", got)
	}
	if got := c2.Effective("work", PresenceTTL); got != "30m" {
		t.Errorf("per-key ttl = %q, want 30m", got)
	}
}

func TestConfigCeiling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{}

	c, _, _ := OpenConfig(path, fc)
	if _, ok := c.Ceiling(); ok {
		t.Error("an unset ceiling should report ok=false")
	}
	c.SetDefault(PresenceMaxTTL, "2h")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if d, ok := c.Ceiling(); !ok || d != 2*time.Hour {
		t.Errorf("Ceiling() = %v, %v, want 2h, true", d, ok)
	}

	// A negative ceiling is nonsense (would reject every ttl) → reported as unset.
	c.SetDefault(PresenceMaxTTL, "-5m")
	if _, ok := c.Ceiling(); ok {
		t.Error("a negative ceiling should report ok=false")
	}
	c.SetDefault(PresenceMaxTTL, "2h")

	// An untrusted store reports no ceiling (fail-closed).
	c.trusted = false
	if _, ok := c.Ceiling(); ok {
		t.Error("an untrusted store should report no ceiling")
	}
}

func TestConfigTTLsAbove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	fc := &fakeCrypto{}

	c, _, _ := OpenConfig(path, fc)
	c.SetDefault(PresenceTTL, "3h")
	c.SetKeyConfig("alpha", PresenceTTL, "4h")
	c.SetKeyConfig("bravo", PresenceTTL, "1h")

	got := c.TTLsAbove(2 * time.Hour)
	want := []TTLRef{{Key: "", Value: "3h"}, {Key: "alpha", Value: "4h"}}
	if len(got) != len(want) {
		t.Fatalf("TTLsAbove = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("TTLsAbove[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
