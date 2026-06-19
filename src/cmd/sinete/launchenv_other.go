// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package main

// prepareLaunchSession is a no-op off macOS: there is no bundled-agent log path
// to set up, and the delegation upstream comes from the inherited SSH_AUTH_SOCK
// (resolved in cmdAgent).
func prepareLaunchSession(string) {}

// launchUIIfDoubleClicked is a no-op off macOS (there is no bundled SwiftUI app).
func launchUIIfDoubleClicked() {}
