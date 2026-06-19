// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package pinentry prompts for a PIN via the GnuPG pinentry program, which renders
// a native dialog per desktop (pinentry-qt/-gnome3 on a graphical session, -curses/
// -tty on a text console) over one Assuan code path. It is used on Linux for the TPM
// master-key PIN and PIN-presence; macOS uses the Secure Enclave's own Touch ID.
package pinentry

import (
	"errors"
	"fmt"
	"os"

	"github.com/twpayne/go-pinentry"
)

// ErrCancelled is returned when the user dismisses the dialog.
var ErrCancelled = errors.New("pinentry: cancelled")

// client opens a pinentry honouring the user's configured program (gpg-agent.conf
// pinentry-program), falling back to the system default `pinentry`, and binds the
// controlling tty so the curses/tty flavours can prompt on a text console.
func client(opts ...pinentry.ClientOption) (*pinentry.Client, error) {
	base := []pinentry.ClientOption{
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
	}
	// pinentry-curses/-tty need a tty; prefer $GPG_TTY, else the controlling /dev/tty.
	if tty := os.Getenv("GPG_TTY"); tty != "" {
		base = append(base, pinentry.WithCommandf("OPTION ttyname=%s", tty))
	} else if _, err := os.Stat("/dev/tty"); err == nil {
		base = append(base, pinentry.WithCommand("OPTION ttyname=/dev/tty"))
	}
	return pinentry.NewClient(append(base, opts...)...)
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
