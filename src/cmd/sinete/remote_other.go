// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

import "net"

// presenceUnavailable is conservatively false off macOS: the Linux backend will add
// logind-based detection (sd_session_is_remote) behind this same seam — see the
// contract in remote.go — but until then we don't refuse anything.
func presenceUnavailable(net.Conn) bool { return false }
