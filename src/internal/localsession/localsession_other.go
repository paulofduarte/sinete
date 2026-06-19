// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package localsession

// RequireLocalSelf has no session backend to consult on these platforms; presence-gated
// operations aren't reachable here anyway (no cryptoprocessor epoch — see the
// cryptoprocessor's other-platform stubs). It is the no-op half of the cross-platform
// local-session gate.
func RequireLocalSelf() error { return nil }
