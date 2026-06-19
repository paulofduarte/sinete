// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build e2e_assume_local

package cryptoprocessor

// requireLocalSession is a TEST-ONLY no-op compiled in only under the e2e_assume_local
// build tag, which the QEMU+swtpm integration harness (src/test/qemu) sets for the
// minimal busybox guest that has no D-Bus/logind. It replaces the real cross-platform
// requireLocalSession (masterauth_local.go, which delegates to internal/localsession).
//
// Production binaries are built by `nix build` WITHOUT this tag, so they always get the
// real check — the bypass exists in no shipped binary. This mirrors the harness's
// test-only fake-pinentry.
func requireLocalSession() error { return nil }
