// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package registry maintains sinete's local index of enclave keys.
//
// sks cannot enumerate an application's keys, so sinete records each key it
// creates here, mapping a human name to its enclave (label, tag) and cached
// public key. The index holds no secret material; it lets list, export and
// fingerprint run without touching the secure hardware.
package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Presence-config setting names (see `sinete config`). Durations parsed with
// time.ParseDuration; the agent applies built-in defaults when unset.
const (
	PresenceTTL    = "presence-ttl"     // idle window; resets on each signature
	PresenceMaxTTL = "presence-max-ttl" // absolute cap from the first signature
)

// Settings lists the recognised config keys.
var Settings = []string{PresenceTTL, PresenceMaxTTL}

// ValidSetting reports whether name is a recognised config key.
func ValidSetting(name string) bool {
	for _, s := range Settings {
		if s == name {
			return true
		}
	}
	return false
}

// Entry records one enclave key and its per-key config overrides.
type Entry struct {
	Name      string            `json:"name"`
	Label     string            `json:"label"`
	Tag       string            `json:"tag"`
	PublicKey string            `json:"publicKey"` // OpenSSH authorized_keys line
	Created   time.Time         `json:"created"`
	Config    map[string]string `json:"config,omitempty"` // per-key setting overrides
}

// fileFormat is the on-disk shape of keys.json: the keys plus global config
// defaults. Older files were a bare []Entry array (still read, see Open).
type fileFormat struct {
	Keys     []Entry           `json:"keys"`
	Defaults map[string]string `json:"defaults,omitempty"`
}

// Registry is the on-disk key index plus global config defaults.
type Registry struct {
	path     string
	entries  map[string]Entry
	defaults map[string]string
}

// DefaultPath returns $XDG_CONFIG_HOME/sinete/keys.json, falling back to
// ~/.config/sinete/keys.json when XDG_CONFIG_HOME is unset.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "sinete", "keys.json"), nil
}

// Open loads the registry at path, returning an empty registry if the file
// does not exist yet.
func Open(path string) (*Registry, error) {
	r := &Registry{path: path, entries: map[string]Entry{}, defaults: map[string]string{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	// An empty or whitespace-only file is a valid empty registry; json would
	// otherwise reject it with "unexpected end of JSON input".
	if len(bytes.TrimSpace(data)) == 0 {
		return r, nil
	}
	// Current format: an object with keys + defaults. Falls back to the legacy
	// bare []Entry array.
	var f fileFormat
	if err := json.Unmarshal(data, &f); err == nil {
		for _, e := range f.Keys {
			r.entries[e.Name] = e
		}
		if f.Defaults != nil {
			r.defaults = f.Defaults
		}
		return r, nil
	}
	var list []Entry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, e := range list {
		r.entries[e.Name] = e
	}
	return r, nil
}

// Get returns the entry for name.
func (r *Registry) Get(name string) (Entry, bool) {
	e, ok := r.entries[name]
	return e, ok
}

// List returns the entries sorted by name.
func (r *Registry) List() []Entry {
	out := make([]Entry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Add inserts or replaces an entry.
func (r *Registry) Add(e Entry) {
	r.entries[e.Name] = e
}

// Remove deletes the entry for name. It is not an error if the name is absent.
func (r *Registry) Remove(name string) {
	delete(r.entries, name)
}

// Effective returns the value of a config setting for a key: the per-key
// override if set, else the global default, else "".
func (r *Registry) Effective(name, setting string) string {
	if e, ok := r.entries[name]; ok {
		if v, ok := e.Config[setting]; ok && v != "" {
			return v
		}
	}
	return r.defaults[setting]
}

// SetDefault sets a global config default.
func (r *Registry) SetDefault(setting, value string) {
	if r.defaults == nil {
		r.defaults = map[string]string{}
	}
	r.defaults[setting] = value
}

// SetKeyConfig sets a per-key config override. It errors if name is unknown.
func (r *Registry) SetKeyConfig(name, setting, value string) error {
	e, ok := r.entries[name]
	if !ok {
		return fmt.Errorf("no key named %q", name)
	}
	if e.Config == nil {
		e.Config = map[string]string{}
	}
	e.Config[setting] = value
	r.entries[name] = e
	return nil
}

// Defaults returns a copy of the global config defaults.
func (r *Registry) Defaults() map[string]string {
	out := make(map[string]string, len(r.defaults))
	for k, v := range r.defaults {
		out[k] = v
	}
	return out
}

// Save writes the registry to disk, replacing it atomically.
func (r *Registry) Save() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileFormat{Keys: r.List(), Defaults: r.defaults}, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
