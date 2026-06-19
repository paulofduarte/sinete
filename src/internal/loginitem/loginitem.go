// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// Package loginitem registers sinete's launchd agent as a macOS login item via
// ServiceManagement (SMAppService). Registering from the signed bundle makes
// macOS attribute the agent to sinete.app (its name and icon) in System Settings
// > Login Items, rather than to a standalone wrapper script. The agent's plist
// is bundled at Contents/Library/LaunchAgents/<PlistName>.
package loginitem

// AgentLabel is the launchd job label. It doubles as the base name of the
// bundled plist and as the XPC_SERVICE_NAME launchd sets on the spawned agent,
// which the CLI uses to recognise a launchd-managed launch.
const AgentLabel = "me.paulofduarte.sinete.agent"

// PlistName is the bundled LaunchAgent plist filename passed to SMAppService.
const PlistName = AgentLabel + ".plist"
