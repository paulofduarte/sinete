// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"os"
	"path/filepath"
	"testing"
)

func writeKeysJSON(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Registry is now the read-only legacy loader used to migrate an old keys.json;
// these cover the two on-disk formats it must still parse, plus the empty and
// malformed cases.

func TestOpenObjectFormat(t *testing.T) {
	path := writeKeysJSON(t, `{
	  "keys": [
	    {"name":"work","label":"sinete-work","tag":"me.paulofduarte.sinete","config":{"presence-ttl":"8h"}},
	    {"name":"alt","label":"sinete-alt","tag":"me.paulofduarte.sinete"}
	  ],
	  "defaults": {"presence-ttl":"10m"}
	}`)
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	list := r.List()
	if len(list) != 2 {
		t.Fatalf("got %d entries, want 2", len(list))
	}
	if list[0].Name != "alt" || list[1].Name != "work" {
		t.Fatalf("entries not sorted by name: %q, %q", list[0].Name, list[1].Name)
	}
	if got := list[1].Config[PresenceTTL]; got != "8h" {
		t.Errorf("work per-key config = %q, want 8h", got)
	}
	if got := r.Defaults()[PresenceTTL]; got != "10m" {
		t.Errorf("default = %q, want 10m", got)
	}
}

func TestOpenLegacyArrayFormat(t *testing.T) {
	path := writeKeysJSON(t, `[{"name":"old","label":"sinete-old","tag":"me.paulofduarte.sinete"}]`)
	r, err := Open(path)
	if err != nil {
		t.Fatalf("legacy array should parse: %v", err)
	}
	list := r.List()
	if len(list) != 1 || list[0].Name != "old" {
		t.Fatalf("legacy array: got %+v, want one entry named old", list)
	}
}

func TestOpenEmptyAndAbsent(t *testing.T) {
	r, err := Open(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("absent file should open empty: %v", err)
	}
	if len(r.List()) != 0 {
		t.Fatal("absent file should be empty")
	}

	r2, err := Open(writeKeysJSON(t, ""))
	if err != nil {
		t.Fatalf("empty file should open empty: %v", err)
	}
	if len(r2.List()) != 0 {
		t.Fatal("empty file should be empty")
	}
}

func TestOpenUnrecognisedObject(t *testing.T) {
	if _, err := Open(writeKeysJSON(t, `{"foo":1}`)); err == nil {
		t.Error("an object without keys/defaults should error")
	}
}

func TestHasConfig(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"no config", `{"keys":[{"name":"a","label":"sinete-a","tag":"t"}]}`, false},
		{"global default", `{"defaults":{"presence-ttl":"10m"}}`, true},
		{"per-key override", `{"keys":[{"name":"a","label":"sinete-a","tag":"t","config":{"presence-ttl":"5m"}}]}`, true},
	}
	for _, c := range cases {
		r, err := Open(writeKeysJSON(t, c.content))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := r.HasConfig(); got != c.want {
			t.Errorf("%s: HasConfig = %v, want %v", c.name, got, c.want)
		}
	}
}
