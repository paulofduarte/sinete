// SPDX-FileCopyrightText: 2026 Paulo Duarte
// SPDX-License-Identifier: Apache-2.0

// sinete-ui is the bundle's double-click face: a small SwiftUI control panel for
// first-run setup and the configured "ready" screen. It carries no entitlements
// and never touches the Secure Enclave directly -- every privileged action is
// performed by the sibling `sinete` CLI (the entitled main executable) which it
// runs as a subprocess. Ongoing in-app key management will instead talk to the
// running agent over its socket.

import AppKit
import SwiftUI

// MARK: - Backend bridge (runs the sibling `sinete` CLI)

enum Backend {
    /// Path to the entitled `sinete` binary, a sibling in Contents/MacOS.
    static var sinetePath: String {
        let exe = Bundle.main.executablePath ?? CommandLine.arguments[0]
        return (exe as NSString).deletingLastPathComponent.appending("/sinete")
    }

    enum RunError: Error, LocalizedError {
        case failed(String)
        var errorDescription: String? {
            if case let .failed(msg) = self { return msg }
            return nil
        }
    }

    @discardableResult
    static func run(_ args: [String]) throws -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: sinetePath)
        proc.arguments = args
        let out = Pipe()
        let err = Pipe()
        proc.standardOutput = out
        proc.standardError = err
        try proc.run()
        // Drain stdout and stderr concurrently: reading one to EOF before the
        // other can deadlock if the child fills the second pipe's buffer.
        var outData = Data()
        var errData = Data()
        let group = DispatchGroup()
        DispatchQueue.global().async(group: group) {
            outData = out.fileHandleForReading.readDataToEndOfFile()
        }
        DispatchQueue.global().async(group: group) {
            errData = err.fileHandleForReading.readDataToEndOfFile()
        }
        group.wait()
        proc.waitUntilExit()
        let stdout = String(data: outData, encoding: .utf8) ?? ""
        let stderr = String(data: errData, encoding: .utf8) ?? ""
        if proc.terminationStatus != 0 {
            let msg = stderr.isEmpty ? stdout : stderr
            throw RunError.failed(msg.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return stdout
    }
}

// MARK: - Models (mirror `sinete status --json` and `sinete install --plan`)

struct KeyInfo: Decodable, Identifiable {
    let name: String
    let type: String
    let fingerprint: String
    var id: String {
        name
    }
}

struct Status: Decodable {
    let configured: Bool
    let method: String?
    let linkPath: String?
    let loginItem: String
    let bundlePath: String?
    let userIsAdmin: Bool
    let keyCount: Int
    let keys: [KeyInfo]
}

struct InstallPlan: Decodable {
    let method: String
    let linkPath: String
    let target: String
    let linkExists: Bool
    let linkConflicts: Bool
}

func loadStatus() -> Status? {
    guard let out = try? Backend.run(["status", "--json"]),
          let data = out.data(using: .utf8),
          let status = try? JSONDecoder().decode(Status.self, from: data)
    else { return nil }
    return status
}

// MARK: - App

@main
struct SineteUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Window("sinete", id: "main") {
            RootView().frame(width: 460, height: 440)
        }
        .windowResizability(.contentSize)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_: NSApplication) -> Bool {
        true
    }
}

// MARK: - Root

struct RootView: View {
    @State private var status: Status?
    @State private var loading = true
    @State private var forceSetup = false
    @State private var errorText: String?

    var body: some View {
        VStack {
            if loading {
                ProgressView("Checking sinete...")
            } else if let status, status.configured, !forceSetup {
                ReadyView(status: status, onReconfigure: { forceSetup = true }, onChanged: reload)
            } else {
                SetupView(status: status, onDone: { forceSetup = false; reload() }, reportError: { errorText = $0 })
            }
        }
        .padding(24)
        .onAppear(perform: reload)
        .alert("Something went wrong",
               isPresented: Binding(get: { errorText != nil }, set: { if !$0 { errorText = nil } })) {
            Button("OK") { errorText = nil }
        } message: {
            Text(errorText ?? "")
        }
    }

    private func reload() {
        loading = true
        DispatchQueue.global().async {
            let loaded = loadStatus()
            DispatchQueue.main.async {
                status = loaded
                loading = false
            }
        }
    }
}

// MARK: - Ready screen

struct ReadyView: View {
    let status: Status
    let onReconfigure: () -> Void
    let onChanged: () -> Void
    @State private var busy = false
    @State private var errorText: String?

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("sinete is fully configured and ready to use")
                .font(.title3).bold()
                .multilineTextAlignment(.center)

            VStack(alignment: .leading, spacing: 6) {
                Label("\(status.keyCount) enclave key\(status.keyCount == 1 ? "" : "s")", systemImage: "key.fill")
                if let method = status.method, let link = status.linkPath {
                    Label("\(method) install at \(link)", systemImage: "terminal")
                }
                Label("login item: \(status.loginItem)", systemImage: "person.badge.clock")
            }
            .font(.callout)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)

            Spacer()

            HStack {
                // Removing a system /usr/local/bin link needs admin rights, so
                // hide Uninstall for a non-admin only when such a link exists.
                // Without one (e.g. --skip-link) uninstall needs no admin.
                if !(status.method == "admin" && status.linkPath != nil && !status.userIsAdmin) {
                    Button("Uninstall", role: .destructive, action: uninstall)
                }
                Button("Reconfigure", action: onReconfigure)
                Button("Information", action: openDocs)
                Spacer()
                Button("Close") { NSApp.terminate(nil) }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .disabled(busy)
        .alert("Something went wrong",
               isPresented: Binding(get: { errorText != nil }, set: { if !$0 { errorText = nil } })) {
            Button("OK") { errorText = nil }
        } message: {
            Text(errorText ?? "")
        }
    }

    private func openDocs() {
        if let url = URL(string: "https://github.com/paulofduarte/sinete") {
            NSWorkspace.shared.open(url)
        }
    }

    private func uninstall() {
        let confirm = NSAlert()
        confirm.messageText = "Uninstall sinete?"
        confirm.informativeText = """
        This removes the login item, the PATH link, and the .pub files sinete \
        created (a link or .pub you chose to keep is left alone). The app is \
        then moved to the Trash.
        """
        confirm.addButton(withTitle: "Uninstall")
        confirm.addButton(withTitle: "Cancel")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        var removeKeys = false
        if status.keyCount > 0 {
            let keyAlert = NSAlert()
            keyAlert.messageText = "Also delete your \(status.keyCount) key\(status.keyCount == 1 ? "" : "s")?"
            var info = """
            This permanently destroys the hardware keys in the Secure Enclave; \
            it cannot be undone. If you keep them, they stay safe and become \
            available again when you reinstall sinete with the same signing identity.
            """
            if status.method == "admin" {
                info += "\n\n" + """
                Only your keys are affected. Other users with sinete keys must \
                run the app in their own account to delete theirs.
                """
            }
            keyAlert.informativeText = info
            keyAlert.addButton(withTitle: "Keep keys")
            keyAlert.addButton(withTitle: "Delete keys")
            keyAlert.addButton(withTitle: "Cancel")
            switch keyAlert.runModal() {
            case .alertSecondButtonReturn: removeKeys = true
            case .alertThirdButtonReturn: return
            default: removeKeys = false
            }
        }

        busy = true
        DispatchQueue.global().async {
            var failure: String?
            do {
                try Backend.run(removeKeys ? ["uninstall", "--remove-keys"] : ["uninstall"])
            } catch { failure = error.localizedDescription }
            DispatchQueue.main.async {
                busy = false
                if let failure {
                    errorText = failure
                    onChanged()
                    return
                }
                trashAppAndQuit()
            }
        }
    }

    private func trashAppAndQuit() {
        // sinete-ui lives in Contents/MacOS; the .app bundle is three levels up.
        let exe = Bundle.main.executablePath ?? CommandLine.arguments[0]
        let macos = (exe as NSString).deletingLastPathComponent
        let contents = (macos as NSString).deletingLastPathComponent
        let bundle = (contents as NSString).deletingLastPathComponent
        if bundle.hasSuffix(".app") {
            do {
                try FileManager.default.trashItem(at: URL(fileURLWithPath: bundle), resultingItemURL: nil)
            } catch {
                // Trashing can fail (e.g. a bundle in /Applications without rights).
                // Uninstall already succeeded, so tell the user to remove it by hand
                // rather than quitting silently while the app is still in place.
                let alert = NSAlert()
                alert.messageText = "Couldn't move sinete to the Trash"
                alert.informativeText = """
                Uninstall finished, but \(bundle) couldn't be moved to the Trash \
                (\(error.localizedDescription)). Delete the app manually.
                """
                alert.runModal()
            }
        }
        NSApp.terminate(nil)
    }
}

// MARK: - Setup wizard

/// The presence-caching fields shown in the install step, split out to keep
/// SetupView's body small. Suggestions are pre-filled; an unconfigured sinete
/// prompts on every signature (strict), so these only relax from that.
private struct PresenceSetupFields: View {
    @Binding var ttl: String
    @Binding var maxTTL: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Presence caching").font(.headline)
            Text("""
            How long Touch ID stays valid before the next prompt. Keep the \
            suggestions, or lower them for stricter prompting. Leaving sinete \
            unconfigured prompts on every signature.
            """)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            HStack {
                Text("Idle TTL").frame(width: 120, alignment: .leading)
                TextField("e.g. 10m", text: $ttl)
                    .textFieldStyle(.roundedBorder).frame(width: 90)
                    .accessibilityLabel("Idle TTL")
            }
            HStack {
                Text("Max TTL (cap)").frame(width: 120, alignment: .leading)
                TextField("e.g. 2h", text: $maxTTL)
                    .textFieldStyle(.roundedBorder).frame(width: 90)
                    .accessibilityLabel("Max TTL cap")
            }
        }
        .frame(maxWidth: 340)
    }
}

/// Shows the link-conflict alert and returns the install arg that resolves it
/// ("--replace-link" or "--skip-link"), or nil if the user cancelled. Must run on
/// the main thread (it presents an NSAlert).
private func resolveLinkConflictArg(_ plan: InstallPlan) -> String? {
    let alert = NSAlert()
    alert.messageText = "Something already exists at the link path"
    alert.informativeText = """
    \(plan.linkPath) already exists and isn't sinete's link. \
    Replace it so it points at sinete, or keep the existing one? \
    If you keep it, sinete isn't added to PATH and won't remove \
    it on uninstall.
    """
    alert.addButton(withTitle: "Replace")
    alert.addButton(withTitle: "Keep existing")
    alert.addButton(withTitle: "Cancel")
    switch alert.runModal() {
    case .alertFirstButtonReturn: return "--replace-link"
    case .alertSecondButtonReturn: return "--skip-link"
    default: return nil
    }
}

struct SetupView: View {
    let status: Status?
    let onDone: () -> Void
    let reportError: (String) -> Void

    @State private var step = 0
    @State private var keyName = ""
    @State private var instructions = ""
    @State private var busy = false
    // Suggested starting values for presence caching; mirror registry.Suggested in
    // Go. These are suggestions, not enforced defaults — an unconfigured sinete
    // prompts on every signature (strict). The user can override before installing.
    @State private var presenceTTL = "10m"
    @State private var presenceMaxTTL = "2h"

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "wand.and.stars")
                .font(.system(size: 40))
                .foregroundStyle(.tint)
            Text("Set up sinete")
                .font(.title2).bold()

            Group {
                switch step {
                case 0:
                    stepInstall
                case 1:
                    stepFirstKey
                case 2:
                    stepSSH
                default:
                    stepInstructions
                }
            }
            .frame(maxWidth: .infinity)

            Spacer()
        }
        .disabled(busy)
        .onAppear { loadCurrentTTLs() }
    }

    /// Pre-fill the presence fields from the current config so reconfiguring an
    /// already-set-up sinete shows (and keeps) its values. When sinete is already set
    /// up — or its status is unknown (decode failed) — the live config is always
    /// reflected, even when both TTLs are empty (an intentionally strict setup), so
    /// clicking Install can't re-suggest relaxed values. Only a confirmed fresh
    /// install keeps the pre-filled suggestions.
    private func loadCurrentTTLs() {
        // Unknown status (nil) is treated as a reconfigure for safety: reflect the
        // real config rather than risk relaxing a strict setup back to suggestions.
        let reconfigure = status?.configured ?? true
        // Snapshot the fields now (main thread, .onAppear) so we don't overwrite any
        // edits the user makes while the async fetch is in flight.
        let startTTL = presenceTTL
        let startMax = presenceMaxTTL
        DispatchQueue.global().async {
            let ttl = (try? Backend.run(["config", "get", "presence-ttl"]))?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let maxTTL = (try? Backend.run(["config", "get", "presence-max-ttl"]))?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            DispatchQueue.main.async {
                // Skip if the user has typed into either field since the fetch began.
                guard presenceTTL == startTTL, presenceMaxTTL == startMax else { return }
                if reconfigure || !ttl.isEmpty || !maxTTL.isEmpty {
                    presenceTTL = ttl
                    presenceMaxTTL = maxTTL
                }
            }
        }
    }

    private var stepInstall: some View {
        VStack(spacing: 12) {
            Text("""
            Put `sinete` on your PATH and start the agent as a login item. \
            You may be asked for your password to create a system link.
            """)
            .multilineTextAlignment(.center)
            .foregroundStyle(.secondary)

            PresenceSetupFields(ttl: $presenceTTL, maxTTL: $presenceMaxTTL)

            Button("Install") { install() }
                .keyboardShortcut(.defaultAction)
        }
    }

    private var stepFirstKey: some View {
        VStack(spacing: 12) {
            Text("Create your first hardware-backed key?")
                .foregroundStyle(.secondary)
            TextField("key name (e.g. your email)", text: $keyName)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 280)
                .accessibilityLabel("Key name")
            HStack {
                Button("Skip") { step = 2 }
                Button("Create") { generate() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(keyName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    /// The key to configure for SSH: the one just created, else the first existing.
    private var sshKeyName: String {
        let typed = keyName.trimmingCharacters(in: .whitespaces)
        if !typed.isEmpty { return typed }
        return status?.keys.first?.name ?? ""
    }

    private var stepSSH: some View {
        VStack(spacing: 12) {
            if keyName.trimmingCharacters(in: .whitespaces).isEmpty, let existing = status?.keys.first {
                Text("You already have the key '\(existing.name)'.")
                    .foregroundStyle(.secondary)
            }
            Text(sshKeyName.isEmpty
                ? "No key to set up yet. Skip, or go back to create one."
                : "Set up '\(sshKeyName)' for SSH and Git signing?")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            HStack {
                Button("Skip") { onDone() }
                Button("Set up SSH") { sshSetup() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(sshKeyName.isEmpty)
            }
        }
    }

    private func install() {
        busy = true
        DispatchQueue.global().async {
            var args = ["install"]
            // Pass the chosen presence TTLs as flags so install writes the signed
            // config (one Touch ID). On a fresh install a missing flag fills from the
            // suggestions; on an existing config install changes only what's passed and
            // leaves a cleared field untouched — so reconfigure never silently relaxes.
            let ttl = presenceTTL.trimmingCharacters(in: .whitespacesAndNewlines)
            let maxTTL = presenceMaxTTL.trimmingCharacters(in: .whitespacesAndNewlines)
            if !ttl.isEmpty { args.append(contentsOf: ["--presence-ttl", ttl]) }
            if !maxTTL.isEmpty { args.append(contentsOf: ["--presence-max-ttl", maxTTL]) }
            if let planOut = try? Backend.run(["install", "--plan"]),
               let data = planOut.data(using: .utf8),
               let plan = try? JSONDecoder().decode(InstallPlan.self, from: data),
               plan.linkConflicts {
                let resolved = DispatchQueue.main.sync { resolveLinkConflictArg(plan) }
                guard let arg = resolved else {
                    DispatchQueue.main.async { busy = false }
                    return
                }
                args.append(arg)
            }
            var failure: String?
            do { try Backend.run(args) } catch { failure = error.localizedDescription }
            // Recompute the key count after install: the pre-install status may be
            // nil or stale (e.g. an earlier status decode failed), which would
            // misroute the wizard to "create first key" even when keys exist.
            var keyCount = status?.keyCount ?? 0
            if failure == nil,
               let out = try? Backend.run(["status", "--json"]),
               let data = out.data(using: .utf8),
               let fresh = try? JSONDecoder().decode(Status.self, from: data) {
                keyCount = fresh.keyCount
            }
            DispatchQueue.main.async {
                busy = false
                if let failure { reportError(failure); return }
                step = keyCount == 0 ? 1 : 2
            }
        }
    }

    private func generate() {
        let name = keyName.trimmingCharacters(in: .whitespaces)
        busy = true
        DispatchQueue.global().async {
            var failure: String?
            do { try Backend.run(["generate", name]) } catch { failure = error.localizedDescription }
            DispatchQueue.main.async {
                busy = false
                if let failure { reportError(failure); return }
                step = 2
            }
        }
    }

    private func sshSetup() {
        let name = sshKeyName
        guard !name.isEmpty else { return }
        let pub = ("~/.ssh/sinete-\(name).pub" as NSString).expandingTildeInPath
        if FileManager.default.fileExists(atPath: pub) {
            let alert = NSAlert()
            alert.messageText = "Public key file already exists"
            alert.informativeText = """
            \(pub) already exists. Overwrite it? If you keep it, sinete leaves \
            it as is and won't remove it on uninstall.
            """
            alert.addButton(withTitle: "Overwrite")
            alert.addButton(withTitle: "Keep")
            if alert.runModal() != .alertFirstButtonReturn {
                onDone() // keep the existing file; finish setup
                return
            }
        }
        busy = true
        DispatchQueue.global().async {
            var failure: String?
            var out = ""
            // Pass the same path we checked for existence, so the CLI writes
            // exactly where this prompt looked (no divergent default derivation).
            do {
                out = try Backend.run(["ssh-setup", name, "--out", pub])
            } catch { failure = error.localizedDescription }
            DispatchQueue.main.async {
                busy = false
                if let failure { reportError(failure); return }
                instructions = sshConfigBlock(from: out)
                step = 3
            }
        }
    }

    private var stepInstructions: some View {
        VStack(spacing: 12) {
            Text("Use the key")
                .font(.headline)
            Text("""
            Run this to sign with the key, then add the public key on your Git \
            host as both an authentication and a signing key.
            """)
            .font(.callout)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            ScrollView {
                Text(highlightedInstructions)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
            }
            .frame(maxHeight: 170)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(.secondary.opacity(0.3)))
            HStack {
                Button("Copy", action: copyInstructions)
                Button("Done") { onDone() }
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    /// sshConfigBlock drops ssh-setup's leading "wrote <path>" line so the block is
    /// just the config to run.
    private func sshConfigBlock(from output: String) -> String {
        let lines = output.components(separatedBy: "\n").drop {
            $0.hasPrefix("wrote ") || $0.trimmingCharacters(in: .whitespaces).isEmpty
        }
        return lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// SwiftUI has no built-in syntax highlighter; dim the comment lines (#...) for
    /// a light, dependency-free pass.
    private var highlightedInstructions: AttributedString {
        var result = AttributedString()
        let lines = instructions.components(separatedBy: "\n")
        for (index, line) in lines.enumerated() {
            var attributed = AttributedString(line)
            if line.trimmingCharacters(in: .whitespaces).hasPrefix("#") {
                attributed.foregroundColor = .secondary
            }
            result += attributed
            if index < lines.count - 1 {
                result += AttributedString("\n")
            }
        }
        return result
    }

    private func copyInstructions() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(instructions, forType: .string)
    }
}
