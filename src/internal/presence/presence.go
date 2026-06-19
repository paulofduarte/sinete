// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package presence performs a user-presence check (Touch ID on macOS) for the
// agent's sign path. The agent calls Authenticate when a key's presence window
// has lapsed; on success it signs and refreshes the window.
package presence

// Authenticate prompts the user to confirm presence with the given reason,
// returning nil on success and an error if it is declined or unavailable. It
// must be called from the main OS thread so the prompt can draw.
//
// The implementation is platform-specific: macOS uses LocalAuthentication
// (presence_darwin.go); Linux is presence-less in v1 and returns nil ("assume
// present"), since there is no prompt mechanism yet (presence_linux.go); other
// platforms return an error (presence_other.go).
