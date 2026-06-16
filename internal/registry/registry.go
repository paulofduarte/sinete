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

// Entry records one enclave key.
type Entry struct {
	Name      string    `json:"name"`
	Label     string    `json:"label"`
	Tag       string    `json:"tag"`
	PublicKey string    `json:"publicKey"` // OpenSSH authorized_keys line
	Created   time.Time `json:"created"`
}

// Registry is the on-disk key index.
type Registry struct {
	path    string
	entries map[string]Entry
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
	r := &Registry{path: path, entries: map[string]Entry{}}
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

// Save writes the registry to disk, replacing it atomically.
func (r *Registry) Save() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r.List(), "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
