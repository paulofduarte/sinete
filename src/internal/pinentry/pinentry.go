// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package pinentry prompts for a PIN on Linux for the TPM master-key PIN and
// PIN-presence (macOS uses the Secure Enclave's own Touch ID). It picks the most
// complete, portable prompt available, in this order:
//
//   - An explicit gpg-agent.conf pinentry-program always wins when it is runnable.
//   - In a graphical session (DISPLAY/WAYLAND_DISPLAY set): a graphical pinentry
//     (pinentry-gnome3/-qt/-gtk-2) — used even when launched from a TTY. If none is
//     installed, fall back to a terminal read when on a TTY, else show a graphical
//     error box saying a pinentry program is required.
//   - Outside a graphical session: pinentry-curses then pinentry-tty (then the generic
//     pinentry); if none is installed, read directly from the terminal.
//
// The terminal fallback reads with echo off via golang.org/x/term, so a PIN can still
// be entered with no pinentry program installed as long as there is a controlling
// terminal. pinentry itself runs directly (no gpg/gpg-agent needed at runtime), but a
// pinentry program is a SEPARATE package from GnuPG (pinentry-curses/-gnome3/-qt/-tty).
package pinentry

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	pinentry "github.com/twpayne/go-pinentry"
	"golang.org/x/term"
)

// ErrCancelled is returned when the user dismisses the dialog or sends EOF at the
// terminal prompt.
var ErrCancelled = errors.New("pinentry: cancelled")

// ttyAvailable reports whether a controlling terminal can be opened. It is a package
// var so tests can simulate headless vs interactive without a real tty.
var ttyAvailable = func() bool { return ttyOpenable(devTTY) }

const devTTY = "/dev/tty"

// prompter is how a single PIN prompt will be performed: via a pinentry program
// (bin set) or by reading from the terminal (terminal true).
type prompter struct {
	bin      string
	terminal bool
}

// selectPrompter resolves the prompt method per the package's portability matrix, or
// returns an error (after best-effort showing a graphical error box) when neither a
// pinentry program nor a terminal is available.
func selectPrompter() (prompter, error) {
	// An explicitly configured, runnable pinentry-program always wins.
	if bin := configuredPinentry(); bin != "" {
		return prompter{bin: bin}, nil
	}
	if hasDisplay() {
		if bin := graphicalPinentry(); bin != "" {
			return prompter{bin: bin}, nil
		}
		if ttyAvailable() {
			return prompter{terminal: true}, nil
		}
		msg := "sinete needs a pinentry program to ask for your PIN in a graphical session — install one, e.g. pinentry-gnome3 or pinentry-qt."
		showGraphicalError(msg)
		return prompter{}, fmt.Errorf("pinentry: %s", msg)
	}
	if bin := textPinentry(); bin != "" {
		return prompter{bin: bin}, nil
	}
	if ttyAvailable() {
		return prompter{terminal: true}, nil
	}
	return prompter{}, errors.New("pinentry: no pinentry program found and no terminal to read a PIN from — install pinentry-curses (or pinentry-tty), or run sinete from a terminal")
}

// Get prompts for an existing PIN. title is the window title, desc the explanatory
// text, prompt the field label. A dismissed dialog (or terminal EOF) returns
// ErrCancelled.
func Get(title, desc, prompt string) (string, error) {
	p, err := selectPrompter()
	if err != nil {
		return "", err
	}
	if p.terminal {
		return readTerminal(desc, prompt)
	}
	return getViaPinentry(p.bin, title, desc, prompt)
}

// Set prompts to choose a new PIN, asking for it twice and returning it only when both
// entries match. A dismissed dialog returns ErrCancelled.
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

// getViaPinentry runs the named pinentry program for a single GETPIN.
func getViaPinentry(bin, title, desc, prompt string) (string, error) {
	c, err := newClient(
		bin,
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

// newClient opens a pinentry using the given program, binding the controlling tty so
// the curses/tty flavours can prompt on a text console — but only a tty we can open.
// Both $GPG_TTY and /dev/tty can name a tty that exists yet isn't usable, so opening
// it is the real test and a stale $GPG_TTY falls through to /dev/tty.
func newClient(bin string, opts ...pinentry.ClientOption) (*pinentry.Client, error) {
	base := []pinentry.ClientOption{pinentry.WithBinaryName(bin)}
	if tty := os.Getenv("GPG_TTY"); tty != "" && ttyOpenable(tty) {
		base = append(base, pinentry.WithCommandf("OPTION ttyname=%s", tty))
	} else if ttyOpenable(devTTY) {
		base = append(base, pinentry.WithCommand("OPTION ttyname="+devTTY))
	}
	return pinentry.NewClient(append(base, opts...)...)
}

// readTerminal reads a PIN from the controlling terminal with echo off. It is the
// fallback when no pinentry program is installed.
func readTerminal(desc, prompt string) (string, error) {
	tty, err := os.OpenFile(devTTY, os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("pinentry: cannot open a terminal to read a PIN: %w", err)
	}
	defer tty.Close()

	if desc != "" {
		fmt.Fprintln(tty, desc)
	}
	fmt.Fprintf(tty, "%s ", prompt)
	pin, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", ErrCancelled
		}
		return "", fmt.Errorf("pinentry: reading PIN from terminal: %w", err)
	}
	if len(pin) == 0 {
		return "", errors.New("pinentry: empty PIN")
	}
	return string(pin), nil
}

// hasDisplay reports whether a graphical session is present.
func hasDisplay() bool {
	return os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("DISPLAY") != ""
}

// configuredPinentry returns the gpg-agent.conf pinentry-program when it is set AND
// runnable; an unset or stale/uninstalled value returns "" so selection falls through
// to the matrix rather than failing later with an opaque exec error.
func configuredPinentry() string {
	p := gpgAgentPinentryProgram()
	if p == "" {
		return ""
	}
	if path, err := exec.LookPath(p); err == nil {
		return path
	}
	return ""
}

// graphicalPinentry returns the first graphical pinentry flavour on PATH, preferring
// the one matching the current desktop, or "" if none is installed.
func graphicalPinentry() string {
	cands := []string{"pinentry-gnome3", "pinentry-qt", "pinentry-gtk-2"}
	if strings.Contains(strings.ToUpper(os.Getenv("XDG_CURRENT_DESKTOP")), "KDE") {
		cands = []string{"pinentry-qt", "pinentry-gnome3", "pinentry-gtk-2"}
	}
	return firstOnPath(cands)
}

// textPinentry returns the first text-mode pinentry on PATH (curses, then tty, then
// the generic name), or "" if none is installed.
func textPinentry() string {
	return firstOnPath([]string{"pinentry-curses", "pinentry-tty", "pinentry"})
}

// firstOnPath returns the absolute path of the first name found on PATH, or "".
func firstOnPath(names []string) string {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

// showGraphicalError best-effort displays a modal error box using whatever common
// dialog tool is installed (zenity/kdialog/xmessage). It is a no-op when none is.
func showGraphicalError(msg string) {
	cmds := [][]string{
		{"zenity", "--error", "--title=sinete", "--text=" + msg},
		{"kdialog", "--title", "sinete", "--error", msg},
		{"xmessage", "-center", msg},
	}
	for _, c := range cmds {
		if path, err := exec.LookPath(c[0]); err == nil {
			_ = exec.Command(path, c[1:]...).Run()
			return
		}
	}
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

// ttyOpenable reports whether path can be opened read-write — the real test of whether
// a tty is usable, since a tty device node can exist without being usable.
func ttyOpenable(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
