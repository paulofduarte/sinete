// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

package pinentry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakePinentry writes a shell script speaking the minimal Assuan protocol and points
// a throwaway GNUPGHOME's gpg-agent.conf at it, so Get/Set drive the fake rather than
// a real pinentry. body is the loop that answers commands.
func fakePinentry(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf 'OK greet\\n'\nwhile IFS= read -r line; do\n" + body + "\ndone\n"
	prog := filepath.Join(dir, "fake-pinentry")
	if err := os.WriteFile(prog, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// We resolve the program from gpg-agent.conf under $GNUPGHOME, so point GNUPGHOME at
	// the throwaway dir to keep the selection deterministic (independent of the
	// developer's / CI runner's real gnupg config) and to exercise the $GNUPGHOME path.
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

func TestNoPinentryFound(t *testing.T) {
	// No gpg-agent.conf and an empty PATH ⇒ no pinentry program ⇒ a clear error.
	t.Setenv("GNUPGHOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")
	_, err := Get("title", "desc", "PIN:")
	if err == nil {
		t.Fatal("Get with no pinentry installed returned nil error")
	}
	if !strings.Contains(err.Error(), "no pinentry program found") {
		t.Errorf("error = %q, want it to mention no pinentry program found", err)
	}
}
