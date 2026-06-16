package registry

import (
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
		Tag:       "dev.sinete",
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
