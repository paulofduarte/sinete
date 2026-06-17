// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package registry holds sinete's per-key presence config.
//
// Which keys exist is determined by enumerating the secure element, not by this
// package. Config lives in a single signed file (see Config / config.go):
// registry.json, whose payload is signed by the enclave master key and bound to
// a replay epoch, so tampering or replay is detected and falls back to built-in
// defaults. The legacy Entry-based Registry (this file) is now a read-only loader
// for an old keys.json, used once to migrate its config into the signed Config.
package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

// nameRE constrains key names to a safe set. A name is reused verbatim as a map
// key, an OpenSSH comment, the sinete-<name>.pub filename component, and an
// allowed_signers principal, so path separators, whitespace, quotes and control
// characters must not appear: it must start with a letter or digit, the rest may
// add '.', '_', '-', '@' and '+'. This makes every name-derived path and shell
// snippet safe by construction (no traversal, no injection).
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]*$`)

// ValidName reports whether name is a safe key name (see nameRE), bounding the
// length so derived filenames stay sane.
func ValidName(name string) error {
	if len(name) > 128 {
		return fmt.Errorf("invalid key name: must be at most 128 characters")
	}
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid key name %q: use letters, digits and . _ - @ + (must start with a letter or digit)", name)
	}
	return nil
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

// Registry is the legacy keys.json index: enclave keys plus global config
// defaults. It is now read-only — keys come from secure-element enumeration and
// config from the signed Config (see config.go); Registry survives only to read
// an old keys.json when migrating its config (see Config.MergeLegacy).
type Registry struct {
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
	r := &Registry{entries: map[string]Entry{}, defaults: map[string]string{}}
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
	// A JSON object is the current {keys, defaults} format, but only when it
	// actually carries one of those fields -- otherwise a corrupt object like
	// {"foo":1} would be read as an empty registry, hiding the corruption. An
	// empty object {} is a valid empty registry; anything else is an error.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err == nil {
		_, hasKeys := probe["keys"]
		_, hasDefaults := probe["defaults"]
		switch {
		case hasKeys || hasDefaults:
			var f fileFormat
			if err := json.Unmarshal(data, &f); err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			for _, e := range f.Keys {
				r.entries[e.Name] = e
			}
			if f.Defaults != nil {
				r.defaults = f.Defaults
			}
			return r, nil
		case len(probe) == 0:
			return r, nil
		default:
			return nil, fmt.Errorf("parse %s: unrecognised registry object (no keys/defaults)", path)
		}
	}

	// Not an object: the legacy bare []Entry array.
	var list []Entry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for _, e := range list {
		r.entries[e.Name] = e
	}
	return r, nil
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

// HasConfig reports whether this legacy registry carries any config — global
// defaults or per-key overrides — i.e. whether a migration is worth doing.
func (r *Registry) HasConfig() bool {
	if len(r.defaults) > 0 {
		return true
	}
	for _, e := range r.entries {
		if len(e.Config) > 0 {
			return true
		}
	}
	return false
}

// Defaults returns a copy of the global config defaults.
func (r *Registry) Defaults() map[string]string {
	out := make(map[string]string, len(r.defaults))
	for k, v := range r.defaults {
		out[k] = v
	}
	return out
}
