// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Crypto signs and verifies the config envelope and tracks the replay epoch. The
// production implementation is enclave.ConfigCrypto (the presence-enforced master
// key + the keychain epoch item); tests use a fake. Sign requires user presence;
// Verify, Epoch and Increment do not.
//
// The epoch is advanced via Increment (returning the new value) rather than a
// SetEpoch(v): a TPM-backed backend can only bump a hardware NV monotonic counter,
// not set it to an arbitrary value, so Increment is the contract both backends can
// honour (macOS implements it as read+1+store, Linux as NV_Increment).
type Crypto interface {
	Sign(payload []byte) (sig []byte, err error)
	Verify(payload, sig []byte) bool
	Epoch() (uint64, error)
	Increment() (uint64, error)
}

// ConfigPath returns $XDG_CONFIG_HOME/sinete/registry.json (the signed,
// config-only registry), falling back to ~/.config/sinete/registry.json.
func ConfigPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "sinete", "registry.json"), nil
}

// cfgEnvelope is the on-disk shape: a signed payload plus its signature.
type cfgEnvelope struct {
	V       int    `json:"v"`
	Alg     string `json:"alg"`
	Payload []byte `json:"payload"` // exact signed bytes (base64 in JSON)
	Sig     []byte `json:"sig"`
}

// cfgPayload is what gets signed: the epoch (replay guard) plus the config. Keys
// are per-name overrides; a name absent here uses the defaults.
type cfgPayload struct {
	Epoch    uint64                       `json:"epoch"`
	Defaults map[string]string            `json:"defaults,omitempty"`
	Keys     map[string]map[string]string `json:"keys,omitempty"`
}

const (
	cfgVersion = 1
	cfgAlg     = "ecdsa-sha2-nistp256"
)

// Config is the signed config store: global defaults + per-key overrides. It is
// keyed by key name and holds no key material — which keys exist is determined by
// enumerating the secure element, not by this file.
type Config struct {
	path     string
	crypto   Crypto
	defaults map[string]string
	keys     map[string]map[string]string
	trusted  bool
}

// OpenConfig loads the signed config. A missing file is an empty, trusted store
// (every setting resolves to 0 — strict — until configured). A
// present-but-untrustworthy file — bad signature, epoch mismatch (replay/stale),
// or corrupt — loads empty and UNtrusted, so Effective yields "" (⇒ strict 0)
// rather than honouring possibly tampered values. Fail-CLOSED: losing or tampering
// with config can only tighten to strict, never relax. The bool reports whether
// on-disk config was trusted: false means a warning is warranted (an absent file
// is trusted, not a warning).
func OpenConfig(path string, crypto Crypto) (*Config, bool, error) {
	c := &Config{
		path:     path,
		crypto:   crypto,
		defaults: map[string]string{},
		keys:     map[string]map[string]string{},
		trusted:  true,
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, true, nil
	}
	if err != nil {
		// Unreadable for some other reason (permissions, I/O, a directory at the
		// path): fail-safe like any other verification failure — untrusted, built-in
		// defaults — so callers can warn and still rewrite it rather than erroring.
		c.trusted = false
		return c, false, nil
	}

	// Any problem from here on is fail-safe: untrusted ⇒ built-in defaults.
	var env cfgEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		c.trusted = false
		return c, false, nil
	}
	if env.V != cfgVersion || env.Alg != cfgAlg {
		// An unrecognised envelope version/alg is a future or corrupt format we
		// can't vouch for — fall back to built-in defaults rather than trust it.
		c.trusted = false
		return c, false, nil
	}
	if !crypto.Verify(env.Payload, env.Sig) {
		c.trusted = false
		return c, false, nil
	}
	var pl cfgPayload
	if err := json.Unmarshal(env.Payload, &pl); err != nil {
		c.trusted = false
		return c, false, nil
	}
	epoch, err := crypto.Epoch()
	if err != nil || pl.Epoch != epoch {
		// Can't confirm freshness, or the file is an old (replayed) revision.
		c.trusted = false
		return c, false, nil
	}
	if pl.Defaults != nil {
		c.defaults = pl.Defaults
	}
	if pl.Keys != nil {
		c.keys = pl.Keys
		// presence-max-ttl is global-only: SetKeyConfig won't store it per-key, but
		// enforce the same invariant at the read boundary so a per-key value can never
		// be honoured or surfaced regardless of what is on disk.
		for name, kc := range c.keys {
			delete(kc, PresenceMaxTTL)
			if len(kc) == 0 {
				delete(c.keys, name)
			}
		}
	}
	return c, true, nil
}

// Trusted reports whether the on-disk config verified (signature + epoch).
func (c *Config) Trusted() bool { return c.trusted }

// Effective returns the configured value of setting for a key: the per-key
// override, else the global default, else "" — and the caller maps "" to the
// strict fallback (0). An untrusted store returns "" for everything (fail-closed).
// presence-max-ttl is GLOBAL-only (a per-key value is never honoured), so it is
// always taken from the global default; it acts as a ceiling on presence-ttl,
// enforced both at set time (see the CLI) and structurally by the agent's
// absolute-cap bound.
func (c *Config) Effective(name, setting string) string {
	if !c.trusted {
		return ""
	}
	if setting != PresenceMaxTTL {
		if kc, ok := c.keys[name]; ok {
			if v, ok := kc[setting]; ok && v != "" {
				return v
			}
		}
	}
	return c.defaults[setting]
}

// Ceiling returns the global presence-max-ttl as a duration and whether it is set
// to a usable (non-empty, parseable) value. An untrusted or unset store returns
// (0, false). The CLI uses it to reject a presence-ttl above the ceiling.
func (c *Config) Ceiling() (time.Duration, bool) {
	if !c.trusted {
		return 0, false
	}
	v := c.defaults[PresenceMaxTTL]
	if v == "" {
		return 0, false
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		// Defensive: the CLI validates non-negative durations before signing, so a
		// trusted config should never hold a negative ceiling — but were one present
		// it would reject every non-negative ttl, so treat it as unset rather than
		// lock the user out.
		return 0, false
	}
	return d, true
}

// TTLRef points at one stored presence-ttl value — the global default (Key == "")
// or a per-key override — for the ceiling-lowering warn/reduce flow.
type TTLRef struct {
	Key   string // "" for the global default
	Value string
}

// TTLsAbove returns every stored presence-ttl (global default first, then per-key
// overrides sorted by name) whose duration exceeds max. Used when lowering
// presence-max-ttl to warn about, and then reduce, the now-too-relaxed values.
// Unparseable values are skipped (they can't be honoured anyway).
func (c *Config) TTLsAbove(max time.Duration) []TTLRef {
	var out []TTLRef
	if v := c.defaults[PresenceTTL]; v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > max {
			out = append(out, TTLRef{Key: "", Value: v})
		}
	}
	for _, name := range c.Names() {
		if v := c.keys[name][PresenceTTL]; v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > max {
				out = append(out, TTLRef{Key: name, Value: v})
			}
		}
	}
	return out
}

// Defaults returns a copy of the global config defaults.
func (c *Config) Defaults() map[string]string {
	out := make(map[string]string, len(c.defaults))
	for k, v := range c.defaults {
		out[k] = v
	}
	return out
}

// KeyConfig returns a copy of a key's overrides (nil if none).
func (c *Config) KeyConfig(name string) map[string]string {
	kc, ok := c.keys[name]
	if !ok {
		return nil
	}
	out := make(map[string]string, len(kc))
	for k, v := range kc {
		out[k] = v
	}
	return out
}

// SetDefault sets a global config default (in memory; call Save to persist).
func (c *Config) SetDefault(setting, value string) {
	c.defaults[setting] = value
}

// SetKeyConfig sets a per-key override (in memory; call Save to persist). It does
// not check that the key exists — callers validate that against enumeration.
// presence-max-ttl is global-only, so it is ignored here and can never be stored
// per-key — keeping the persisted model consistent with how Effective resolves it
// (and the CLI rejects it up front, with a message).
func (c *Config) SetKeyConfig(name, setting, value string) {
	if setting == PresenceMaxTTL {
		return
	}
	if c.keys[name] == nil {
		c.keys[name] = map[string]string{}
	}
	c.keys[name][setting] = value
}

// UnsetDefault removes a global default so the setting resolves to strict (in
// memory; call Save to persist). It is not an error if the setting was unset.
func (c *Config) UnsetDefault(setting string) { delete(c.defaults, setting) }

// UnsetKeyConfig removes one setting from a key's overrides, dropping the key
// entry entirely when no overrides remain (in memory; call Save to persist).
func (c *Config) UnsetKeyConfig(name, setting string) {
	kc, ok := c.keys[name]
	if !ok {
		return
	}
	delete(kc, setting)
	if len(kc) == 0 {
		delete(c.keys, name)
	}
}

// RemoveKey drops a key's overrides, e.g. when the key is deleted (in memory;
// call Save to persist). It is not an error if the name has no config.
func (c *Config) RemoveKey(name string) { delete(c.keys, name) }

// HasKey reports whether a name has any stored config.
func (c *Config) HasKey(name string) bool { _, ok := c.keys[name]; return ok }

// Names returns, sorted, the key names that have stored config.
func (c *Config) Names() []string {
	out := make([]string, 0, len(c.keys))
	for n := range c.keys {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Save signs and writes the config, advancing the epoch. Write order is: sign
// with epoch+1 → write the file atomically → store epoch+1. A crash before the
// last step leaves a file whose epoch no longer matches, so it loads as untrusted
// (⇒ strict 0) — fail-closed; re-applying the change fixes it. Save requires user
// presence (the master-key signature prompts).
func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	// Serialise concurrent writers so the epoch read → sign → write → advance is
	// atomic: otherwise two processes could both read epoch N and sign distinct
	// payloads at N+1, letting one be replayed later (it would still match the
	// keychain epoch). The lock is held across the signing prompt. lockConfig is a
	// real flock on unix; the no-op stub elsewhere only keeps the package compiling,
	// where Save can't succeed anyway (no secure-element backend), so nothing relies
	// on the lock there.
	unlock, err := lockConfig(c.path)
	if err != nil {
		return fmt.Errorf("lock config: %w", err)
	}
	defer unlock()

	cur, err := c.crypto.Epoch()
	if err != nil {
		return fmt.Errorf("read epoch: %w", err)
	}
	if cur == math.MaxUint64 {
		// Refuse rather than wrap to 0, which would break replay protection.
		return fmt.Errorf("config epoch exhausted")
	}
	next := cur + 1

	payload, err := json.Marshal(cfgPayload{Epoch: next, Defaults: c.defaults, Keys: c.keys})
	if err != nil {
		return err
	}
	sig, err := c.crypto.Sign(payload)
	if err != nil {
		return fmt.Errorf("sign config: %w", err)
	}
	data, err := json.MarshalIndent(cfgEnvelope{V: cfgVersion, Alg: cfgAlg, Payload: payload, Sig: sig}, "", "  ")
	if err != nil {
		return err
	}

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return err
	}
	// Advance the epoch by one. Under the config lock the read above is stable, so
	// Increment lands on next; if it can't (or somehow lands elsewhere), the on-disk
	// file no longer matches the stored epoch, so a reload distrusts it — mark this
	// instance untrusted too to stay fail-safe and consistent with OpenConfig.
	got, err := c.crypto.Increment()
	if err != nil {
		c.trusted = false
		return fmt.Errorf("advance epoch: %w", err)
	}
	if got != next {
		c.trusted = false
		return fmt.Errorf("advance epoch: got %d, expected %d", got, next)
	}
	c.trusted = true
	return nil
}
