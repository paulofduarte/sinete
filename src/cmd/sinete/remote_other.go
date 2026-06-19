// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package main

import "net"

// presenceUnavailable is conservatively false on platforms without a remote-session
// detector (macOS uses the audit session; Linux uses logind — see remote_linux.go
// and the contract in remote.go); until one exists for a platform we refuse nothing.
func presenceUnavailable(net.Conn) bool { return false }
