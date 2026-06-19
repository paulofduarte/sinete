// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package pinentry prompts for a PIN via the GnuPG pinentry program, which renders
// a native dialog per desktop (pinentry-qt/-gnome3 on a graphical session, -curses/
// -tty on a text console) over one Assuan code path. It is used on Linux for the TPM
// master-key PIN and PIN-presence; macOS uses the Secure Enclave's own Touch ID.
//
// It runs the pinentry program directly (no gpg/gpg-agent needed at runtime), but a
// pinentry program MUST be installed — the standalone `pinentry` package (which
// provides pinentry-curses/-gnome3/-qt/-tty), separate from GnuPG. When none is found
// the prompt functions return a clear "install pinentry" error.
package pinentry

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/twpayne/go-pinentry"
)

// ErrCancelled is returned when the user dismisses the dialog.
var ErrCancelled = errors.New("pinentry: cancelled")

// client opens a pinentry using a desktop-appropriate program, and binds the
// controlling tty so the curses/tty flavours can prompt on a text console.
func client(opts ...pinentry.ClientOption) (*pinentry.Client, error) {
	bin, err := pinentryBinary()
	if err != nil {
		return nil, err
	}
	base := []pinentry.ClientOption{pinentry.WithBinaryName(bin)}
	// pinentry-curses/-tty need a tty; prefer $GPG_TTY, else the controlling /dev/tty
	// — but only if it is actually openable. /dev/tty exists even when the process has
	// no controlling terminal, so a stat would be misleading; opening it is the real
	// test, and we don't bind a tty we can't use.
	if tty := os.Getenv("GPG_TTY"); tty != "" {
		base = append(base, pinentry.WithCommandf("OPTION ttyname=%s", tty))
	} else if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		_ = f.Close()
		base = append(base, pinentry.WithCommand("OPTION ttyname=/dev/tty"))
	}
	return pinentry.NewClient(append(base, opts...)...)
}

// pinentryBinary chooses the pinentry program: an explicit gpg-agent.conf
// pinentry-program if the user configured one, else the first desktop-appropriate
// candidate found on PATH. It does NOT require gpg to be installed — it only reads a
// config file and probes PATH. Returns a clear error when no program is installed.
func pinentryBinary() (string, error) {
	if p := gpgAgentPinentryProgram(); p != "" {
		return p, nil
	}
	cands := pinentryCandidates()
	for _, name := range cands {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("pinentry: no pinentry program found on PATH (tried %s) — install one, e.g. pinentry-curses or pinentry-gnome3", strings.Join(cands, ", "))
}

// pinentryCandidates lists pinentry program names in preference order: a graphical
// flavour for the current desktop when a display is present, then the terminal
// flavours and the generic name (which work without a display).
func pinentryCandidates() []string {
	var c []string
	if os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("DISPLAY") != "" {
		if strings.Contains(strings.ToUpper(os.Getenv("XDG_CURRENT_DESKTOP")), "KDE") {
			c = append(c, "pinentry-qt", "pinentry-gnome3")
		} else {
			c = append(c, "pinentry-gnome3", "pinentry-qt")
		}
		c = append(c, "pinentry-gtk-2")
	}
	return append(c, "pinentry-curses", "pinentry-tty", "pinentry")
}

// gpgAgentPinentryProgram returns the pinentry-program set in the user's
// gpg-agent.conf, or "" if unset/absent. Reading the file does not require gpg to be
// installed.
func gpgAgentPinentryProgram() string {
	dir := gnupgHome()
	if dir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, "gpg-agent.conf"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "pinentry-program" {
			return fields[1]
		}
	}
	return ""
}

// gnupgHome returns GnuPG's home directory: $GNUPGHOME when set (GnuPG honours it to
// relocate the whole config), else $HOME/.gnupg. Returns "" if neither resolves.
func gnupgHome() string {
	if h := os.Getenv("GNUPGHOME"); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".gnupg")
}

// Get prompts for an existing PIN. title is the window title, desc the explanatory
// text, prompt the field label. A dismissed dialog returns ErrCancelled.
func Get(title, desc, prompt string) (string, error) {
	c, err := client(
		pinentry.WithTitle(title),
		pinentry.WithDesc(desc),
		pinentry.WithPrompt(prompt),
	)
	if err != nil {
		return "", err
	}
	defer c.Close()

	pin, _, err := c.GetPIN()
	if err != nil {
		if pinentry.IsCancelled(err) {
			return "", ErrCancelled
		}
		return "", err
	}
	if pin == "" {
		return "", errors.New("pinentry: empty PIN")
	}
	return pin, nil
}

// Set prompts to choose a new PIN, asking for it twice and returning it only when
// both entries match. A dismissed dialog returns ErrCancelled.
func Set(title, desc string) (string, error) {
	first, err := Get(title, desc, "New PIN:")
	if err != nil {
		return "", err
	}
	second, err := Get(title, "Confirm the PIN.", "Confirm PIN:")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("pinentry: the PINs did not match")
	}
	return first, nil
}
