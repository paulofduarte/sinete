// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDetectMethod(t *testing.T) {
	const home = "/Users/alice"
	cases := []struct {
		path string
		want Method
	}{
		{"/Applications/sinete.app", Admin},
		{"/Applications/Utilities/sinete.app", Admin},
		{"/Users/alice/Developer/sinete.app", User},
		{"/Users/alice/sinete.app", User},
		{"/opt/sinete.app", Admin},
		{"/Users/bob/sinete.app", Admin}, // another user's home is not ours -> admin
	}
	for _, c := range cases {
		if got := DetectMethod(c.path, home); got != c.want {
			t.Errorf("DetectMethod(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestStateRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if s, err := LoadState(); err != nil || s != nil {
		t.Fatalf("LoadState on empty = (%v, %v); want (nil, nil)", s, err)
	}
	in := &State{
		Method:       Admin,
		LinkPath:     "/usr/local/bin/sinete",
		BundlePath:   "/Applications/sinete.app",
		ConfiguredAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := in.Save(); err != nil {
		t.Fatal(err)
	}
	out, err := LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Method != in.Method || out.LinkPath != in.LinkPath || !out.ConfiguredAt.Equal(in.ConfiguredAt) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
	if err := RemoveState(); err != nil {
		t.Fatal(err)
	}
	if s, _ := LoadState(); s != nil {
		t.Fatalf("after RemoveState, LoadState = %+v; want nil", s)
	}
}

func TestInspectLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")

	p := &Plan{LinkPath: link, Target: target}
	inspectLink(p)
	if p.LinkExists {
		t.Error("absent link reported as existing")
	}

	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	p = &Plan{LinkPath: link, Target: target}
	inspectLink(p)
	if !p.LinkExists || p.LinkConflicts {
		t.Errorf("correct link: exists=%v conflicts=%v; want true,false", p.LinkExists, p.LinkConflicts)
	}

	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(link)
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	p = &Plan{LinkPath: link, Target: target}
	inspectLink(p)
	if !p.LinkConflicts {
		t.Error("link to a different target: expected a conflict")
	}

	// A relatively-spelled symlink that resolves to the same target must not be
	// reported as a conflict (it would trigger a needless "Replace" prompt).
	_ = os.Remove(link)
	if err := os.Symlink("target", link); err != nil { // relative to dir
		t.Fatal(err)
	}
	p = &Plan{LinkPath: link, Target: target}
	inspectLink(p)
	if p.LinkConflicts {
		t.Error("relative symlink to the same target reported as a conflict")
	}
}

func TestSameTarget(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	if err := os.WriteFile(a, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(b, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, x, y string
		want       bool
	}{
		{"identical", a, a, true},
		{"uncleaned path", a, filepath.Join(dir, ".", "a"), true},
		{"symlink resolves to same file", link, a, true},
		{"different files", a, b, false},
		{"nonexistent", a, filepath.Join(dir, "nope"), false},
	}
	for _, c := range cases {
		if got := sameTarget(c.x, c.y); got != c.want {
			t.Errorf("%s: sameTarget(%q,%q) = %v, want %v", c.name, c.x, c.y, got, c.want)
		}
	}
}

func TestRecordPub(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	// No state yet: RecordPub is a silent no-op (standalone ssh-setup).
	if err := RecordPub("/tmp/a.pub"); err != nil {
		t.Fatalf("RecordPub without state: %v", err)
	}
	if s, _ := LoadState(); s != nil {
		t.Fatalf("RecordPub created state where there was none: %+v", s)
	}

	if err := (&State{Method: User, ConfiguredAt: time.Now().UTC()}).Save(); err != nil {
		t.Fatal(err)
	}
	if err := RecordPub("/tmp/a.pub"); err != nil {
		t.Fatal(err)
	}
	if err := RecordPub("/tmp/a.pub"); err != nil { // duplicate
		t.Fatal(err)
	}
	if err := RecordPub("/tmp/b.pub"); err != nil {
		t.Fatal(err)
	}
	s, err := LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Pubs) != 2 || s.Pubs[0] != "/tmp/a.pub" || s.Pubs[1] != "/tmp/b.pub" {
		t.Fatalf("Pubs = %v; want [/tmp/a.pub /tmp/b.pub] (deduped)", s.Pubs)
	}
}
