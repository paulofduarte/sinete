// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

// prepareLaunchSession is a no-op off macOS: there is no launchd GUI domain to
// republish into, so the upstream (if any) comes from SINETE_UPSTREAM_SOCK as set
// by the caller.
func prepareLaunchSession(string) {}
