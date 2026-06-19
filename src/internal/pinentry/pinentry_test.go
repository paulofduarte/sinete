// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package pinentry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePinentry writes a shell script speaking the minimal Assuan protocol and points a
// throwaway $GNUPGHOME's gpg-agent.conf at it, so Get/Set drive the fake rather than a
// real pinentry (the configured-program path always wins). body is the loop that
// answers commands.
func fakePinentry(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf 'OK greet\\n'\nwhile IFS= read -r line; do\n" + body + "\ndone\n"
	prog := filepath.Join(dir, "fake-pinentry")
	if err := os.WriteFile(prog, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	gnupg := filepath.Join(dir, ".gnupg")
	if err := os.MkdirAll(gnupg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gnupg, "gpg-agent.conf"), []byte("pinentry-program "+prog+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupg)
	t.Setenv("GPG_TTY", "")
}

// returnPIN answers GETPIN with pin; cancel answers with the Assuan cancelled error.
const (
	returnPIN = `  case "$line" in
  GETPIN) printf 'D 1234\n'; printf 'OK\n' ;;
  BYE) printf 'OK\n'; exit 0 ;;
  *) printf 'OK\n' ;;
  esac`
	cancel = `  case "$line" in
  GETPIN) printf 'ERR 83886179 Operation cancelled\n' ;;
  BYE) printf 'OK\n'; exit 0 ;;
  *) printf 'OK\n' ;;
  esac`
)

func TestGet(t *testing.T) {
	fakePinentry(t, returnPIN)
	pin, err := Get("title", "desc", "PIN:")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if pin != "1234" {
		t.Errorf("Get = %q, want 1234", pin)
	}
}

func TestGetCancelled(t *testing.T) {
	fakePinentry(t, cancel)
	if _, err := Get("title", "desc", "PIN:"); !errors.Is(err, ErrCancelled) {
		t.Errorf("Get on cancel = %v, want ErrCancelled", err)
	}
}

func TestSetMatching(t *testing.T) {
	// Both prompts run the same fake, so both return 1234 and Set returns it.
	fakePinentry(t, returnPIN)
	pin, err := Set("title", "desc")
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if pin != "1234" {
		t.Errorf("Set = %q, want 1234", pin)
	}
}

// clearEnv neutralises every signal selectPrompter reads, for a clean baseline.
func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GNUPGHOME", t.TempDir()) // empty dir ⇒ no gpg-agent.conf
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("XDG_CURRENT_DESKTOP", "")
	t.Setenv("GPG_TTY", "")
	t.Setenv("PATH", "")
}

// withTTY overrides the controlling-terminal probe for the test.
func withTTY(t *testing.T, ok bool) {
	t.Helper()
	prev := ttyAvailable
	ttyAvailable = func() bool { return ok }
	t.Cleanup(func() { ttyAvailable = prev })
}

// pathWith writes empty executables for each name into one dir and sets PATH to it.
func pathWith(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return dir
}

func TestSelectPrompter(t *testing.T) {
	tests := []struct {
		name      string
		display   string
		desktop   string
		install   []string // pinentry programs to place on PATH
		tty       bool
		wantBin   string // basename of the chosen program, "" if terminal/error expected
		wantTerm  bool
		wantError bool
	}{
		{name: "graphical uses graphical pinentry even on a tty", display: ":0", install: []string{"pinentry-gnome3"}, tty: true, wantBin: "pinentry-gnome3"},
		{name: "KDE prefers qt", display: ":0", desktop: "KDE", install: []string{"pinentry-qt", "pinentry-gnome3"}, wantBin: "pinentry-qt"},
		{name: "graphical, no pinentry, tty ⇒ terminal", display: "wayland-0", tty: true, wantTerm: true},
		{name: "graphical, no pinentry, no tty ⇒ error", display: ":0", tty: false, wantError: true},
		{name: "non-graphical prefers curses", install: []string{"pinentry-curses", "pinentry-tty"}, tty: true, wantBin: "pinentry-curses"},
		{name: "non-graphical falls back to tty flavour", install: []string{"pinentry-tty"}, tty: true, wantBin: "pinentry-tty"},
		{name: "non-graphical, no pinentry, tty ⇒ terminal", tty: true, wantTerm: true},
		{name: "non-graphical, no pinentry, no tty ⇒ error", tty: false, wantError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			if tc.display != "" {
				if strings.HasPrefix(tc.display, "wayland") {
					t.Setenv("WAYLAND_DISPLAY", tc.display)
				} else {
					t.Setenv("DISPLAY", tc.display)
				}
			}
			if tc.desktop != "" {
				t.Setenv("XDG_CURRENT_DESKTOP", tc.desktop)
			}
			if len(tc.install) > 0 {
				pathWith(t, tc.install...)
			}
			withTTY(t, tc.tty)

			p, err := selectPrompter()
			if tc.wantError {
				if err == nil {
					t.Fatalf("selectPrompter() = %+v, want error", p)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectPrompter: %v", err)
			}
			if p.terminal != tc.wantTerm {
				t.Errorf("terminal = %v, want %v", p.terminal, tc.wantTerm)
			}
			if got := filepath.Base(p.bin); tc.wantBin != "" && got != tc.wantBin {
				t.Errorf("bin = %q, want %q", got, tc.wantBin)
			}
			if tc.wantBin == "" && !tc.wantTerm && p.bin != "" {
				t.Errorf("bin = %q, want none", p.bin)
			}
		})
	}
}

func TestConfiguredPinentryOverridesMatrix(t *testing.T) {
	// A runnable configured program wins even in a graphical session with a graphical
	// pinentry installed.
	clearEnv(t)
	t.Setenv("DISPLAY", ":0")
	pathWith(t, "pinentry-gnome3")
	dir := t.TempDir()
	prog := filepath.Join(dir, "my-pinentry")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gnupg := filepath.Join(t.TempDir(), ".gnupg")
	if err := os.MkdirAll(gnupg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gnupg, "gpg-agent.conf"), []byte("pinentry-program "+prog+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupg)

	p, err := selectPrompter()
	if err != nil {
		t.Fatalf("selectPrompter: %v", err)
	}
	if p.bin != prog {
		t.Errorf("bin = %q, want configured %q", p.bin, prog)
	}
}

func TestConfiguredPinentryStaleFallsThrough(t *testing.T) {
	// A configured-but-missing program must not pin selection to it; with no display
	// and no tty that surfaces as the clear no-pinentry error.
	clearEnv(t)
	gnupg := filepath.Join(t.TempDir(), ".gnupg")
	if err := os.MkdirAll(gnupg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gnupg, "gpg-agent.conf"), []byte("pinentry-program /nonexistent/pinentry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupg)
	withTTY(t, false)

	if _, err := selectPrompter(); err == nil {
		t.Fatal("selectPrompter with stale configured program returned nil error")
	}
}
