// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && e2e_assume_local)

package cryptoprocessor

import "github.com/paulofduarte/sinete/internal/localsession"

// requireLocalSession refuses a master-key operation unless this process runs in a
// local session. It is one cross-platform call into internal/localsession, which holds
// the platform-specific implementations of the SAME check: logind/elogind on Linux,
// SessionGetInfo on macOS, a no-op where there is no session backend. EnsureMaster and
// MasterSign call it FIRST, before any TPM/Secure Enclave access, so a remote session
// is turned away early.
func requireLocalSession() error { return localsession.RequireLocalSelf() }
