// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Crypto signs and verifies the config envelope and tracks the replay epoch. The
// production implementation is enclave.ConfigCrypto (the presence-enforced master
// key + the keychain epoch item); tests use a fake. Sign requires user presence;
// Verify, Epoch and SetEpoch do not.
type Crypto interface {
	Sign(payload []byte) (sig []byte, err error)
	Verify(payload, sig []byte) bool
	Epoch() (uint64, error)
	SetEpoch(uint64) error
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

const cfgAlg = "ecdsa-sha2-nistp256"

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
// (everything uses built-in defaults). A present-but-untrustworthy file — bad
// signature, epoch mismatch (replay/stale), or corrupt — loads empty and
// UNtrusted, so Effective yields built-in defaults rather than honouring possibly
// tampered values. The bool reports whether on-disk config was trusted: false
// means a warning is warranted (an absent file is trusted, not a warning).
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
		return nil, false, err
	}

	// Any problem from here on is fail-safe: untrusted ⇒ built-in defaults.
	var env cfgEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
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
	}
	return c, true, nil
}

// Trusted reports whether the on-disk config verified (signature + epoch).
func (c *Config) Trusted() bool { return c.trusted }

// Effective returns the configured value of setting for a key: the per-key
// override, else the global default, else "" (the caller applies the built-in
// default). An untrusted store returns "" for everything — the fail-safe.
func (c *Config) Effective(name, setting string) string {
	if !c.trusted {
		return ""
	}
	if kc, ok := c.keys[name]; ok {
		if v, ok := kc[setting]; ok && v != "" {
			return v
		}
	}
	return c.defaults[setting]
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
func (c *Config) SetKeyConfig(name, setting, value string) {
	if c.keys[name] == nil {
		c.keys[name] = map[string]string{}
	}
	c.keys[name][setting] = value
}

// RemoveKey drops a key's overrides, e.g. when the key is deleted (in memory;
// call Save to persist). It is not an error if the name has no config.
func (c *Config) RemoveKey(name string) { delete(c.keys, name) }

// HasKey reports whether a name has any stored config.
func (c *Config) HasKey(name string) bool { _, ok := c.keys[name]; return ok }

// Save signs and writes the config, advancing the epoch. Write order is: sign
// with epoch+1 → write the file atomically → store epoch+1. A crash before the
// last step leaves a file whose epoch no longer matches, so it loads as untrusted
// (built-in defaults) — fail-safe; re-applying the change fixes it. Save requires
// user presence (the master-key signature prompts).
func (c *Config) Save() error {
	cur, err := c.crypto.Epoch()
	if err != nil {
		return fmt.Errorf("read epoch: %w", err)
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
	data, err := json.MarshalIndent(cfgEnvelope{V: 1, Alg: cfgAlg, Payload: payload, Sig: sig}, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return err
	}
	if err := c.crypto.SetEpoch(next); err != nil {
		return fmt.Errorf("advance epoch: %w", err)
	}
	c.trusted = true
	return nil
}
