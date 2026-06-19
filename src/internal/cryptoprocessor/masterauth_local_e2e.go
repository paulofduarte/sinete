// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build linux && e2e_assume_local

package cryptoprocessor

// requireLocalSession is a TEST-ONLY no-op compiled in only under the e2e_assume_local
// build tag, which the QEMU+swtpm integration harness (src/test/qemu) sets. That guest
// is a minimal busybox initramfs with no D-Bus/logind, so the real check (which calls
// org.freedesktop.login1) can't run there; the guest IS local (the console), so the
// harness asserts that with this tag to exercise the TPM master-key path.
//
// Production binaries are built by `nix build` WITHOUT this tag, so they always get
// the real requireLocalSession in masterauth_local_linux.go — the bypass does not
// exist in any shipped binary. This mirrors the harness's test-only fake-pinentry.
func requireLocalSession() error { return nil }
