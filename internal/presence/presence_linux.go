// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package presence

// Authenticate is presence-less on Linux in v1: there is no built-in prompt
// mechanism yet (fprintd / pinentry land with the presence work — step 2), so the
// agent signs enclave keys without a presence gate. It returns nil ("assume
// present"), which makes the agent's per-key presence window a silent no-op.
//
// SECURITY DELTA vs macOS: the TPM keys are still hardware-backed and every
// signature is computed in-hardware, but there is no Secure-Enclave-style entitlement
// wall and no presence confirmation, so any same-user process that can reach the
// agent socket (mode 0600, in a 0700 dir) can use the keys. See
// .claude/LINUX-PRESENCE.md and .claude/LINUX-INSTALL.md.
func Authenticate(string) error { return nil }
