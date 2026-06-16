// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.List()); got != 0 {
		t.Fatalf("new registry: got %d entries, want 0", got)
	}

	r.Add(Entry{
		Name:      "work",
		Label:     "sinete-work",
		Tag:       "me.paulofduarte.sinete",
		PublicKey: "ecdsa-sha2-nistp256 AAAA work",
		Created:   time.Unix(0, 0).UTC(),
	})
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r2.Get("work")
	if !ok {
		t.Fatal("entry missing after reload")
	}
	if got.Label != "sinete-work" {
		t.Errorf("label = %q, want sinete-work", got.Label)
	}

	r2.Remove("work")
	if _, ok := r2.Get("work"); ok {
		t.Error("entry still present after remove")
	}
}

func TestOpenEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatalf("empty file should open as an empty registry: %v", err)
	}
	if got := len(r.List()); got != 0 {
		t.Fatalf("got %d entries, want 0", got)
	}
}

func TestConfigDefaultsAndOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.Add(Entry{Name: "work", Label: "sinete-work", Tag: "me.paulofduarte.sinete"})
	r.SetDefault(PresenceTTL, "10m")
	if err := r.SetKeyConfig("work", PresenceTTL, "8h"); err != nil {
		t.Fatal(err)
	}
	if err := r.SetKeyConfig("missing", PresenceTTL, "1h"); err == nil {
		t.Error("SetKeyConfig on an unknown key should error")
	}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	r2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := r2.Effective("work", PresenceTTL); got != "8h" {
		t.Errorf("work %s = %q, want 8h (per-key override)", PresenceTTL, got)
	}
	if got := r2.Effective("other", PresenceTTL); got != "10m" {
		t.Errorf("other %s = %q, want 10m (default)", PresenceTTL, got)
	}
	if got := r2.Effective("work", PresenceMaxTTL); got != "" {
		t.Errorf("unset setting = %q, want empty", got)
	}
}

func TestOpenLegacyArrayFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`[{"name":"old","label":"sinete-old","tag":"me.paulofduarte.sinete"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatalf("legacy array should parse: %v", err)
	}
	if _, ok := r.Get("old"); !ok {
		t.Fatal("entry from legacy array missing")
	}
}

func TestListSorted(t *testing.T) {
	r, err := Open(filepath.Join(t.TempDir(), "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	r.Add(Entry{Name: "b"})
	r.Add(Entry{Name: "a"})
	r.Add(Entry{Name: "c"})

	list := r.List()
	for i, want := range []string{"a", "b", "c"} {
		if list[i].Name != want {
			t.Errorf("list[%d] = %q, want %q", i, list[i].Name, want)
		}
	}
}
