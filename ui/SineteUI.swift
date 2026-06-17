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
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
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
    var id: String { name }
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
            RootView().frame(width: 460, height: 380)
        }
        .windowResizability(.contentSize)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
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
                ProgressView("Checking sinete…")
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
                    Label("\(method) install · \(link)", systemImage: "terminal")
                }
                Label("login item: \(status.loginItem)", systemImage: "person.badge.clock")
            }
            .font(.callout)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)

            Spacer()

            HStack {
                // An all-users install can only be removed by an admin (the
                // system link needs admin rights), so hide Uninstall otherwise.
                if !(status.method == "admin" && !status.userIsAdmin) {
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
        confirm.informativeText = "This removes the login item, the PATH link, and the .pub files sinete created (a link or .pub you chose to keep is left alone). The app is then moved to the Trash."
        confirm.addButton(withTitle: "Uninstall")
        confirm.addButton(withTitle: "Cancel")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        var removeKeys = false
        if status.keyCount > 0 {
            let keyAlert = NSAlert()
            keyAlert.messageText = "Also delete your \(status.keyCount) key\(status.keyCount == 1 ? "" : "s")?"
            var info = "This permanently destroys the hardware keys in the Secure Enclave — it cannot be undone. If you keep them, they stay safe and become available again when you reinstall sinete with the same signing identity."
            if status.method == "admin" {
                info += "\n\nOnly your keys are affected. Other users with sinete keys must run the app in their own account to delete theirs."
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
            try? FileManager.default.trashItem(at: URL(fileURLWithPath: bundle), resultingItemURL: nil)
        }
        NSApp.terminate(nil)
    }
}

// MARK: - Setup wizard

struct SetupView: View {
    let status: Status?
    let onDone: () -> Void
    let reportError: (String) -> Void

    @State private var step = 0
    @State private var keyName = ""
    @State private var busy = false

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
                default:
                    stepSSH
                }
            }
            .frame(maxWidth: .infinity)

            Spacer()
        }
        .disabled(busy)
    }

    private var stepInstall: some View {
        VStack(spacing: 12) {
            Text("Put `sinete` on your PATH and start the agent as a login item. You may be asked for your password to create a system link.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
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
            HStack {
                Button("Skip") { step = 2 }
                Button("Create") { generate() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(keyName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    // The key to configure for SSH: the one just created, else the first existing.
    private var sshKeyName: String {
        let typed = keyName.trimmingCharacters(in: .whitespaces)
        if !typed.isEmpty { return typed }
        return status?.keys.first?.name ?? ""
    }

    private var stepSSH: some View {
        VStack(spacing: 12) {
            if keyName.trimmingCharacters(in: .whitespaces).isEmpty, let existing = status?.keys.first {
                Text("You already have the key “\(existing.name)”.")
                    .foregroundStyle(.secondary)
            }
            Text(sshKeyName.isEmpty
                ? "No key to set up yet — skip, or go back to create one."
                : "Set up “\(sshKeyName)” for SSH and Git signing?")
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
            if let planOut = try? Backend.run(["install", "--plan"]),
               let data = planOut.data(using: .utf8),
               let plan = try? JSONDecoder().decode(InstallPlan.self, from: data),
               plan.linkConflicts {
                let choice = DispatchQueue.main.sync { () -> Int in
                    let alert = NSAlert()
                    alert.messageText = "A different link already exists"
                    alert.informativeText = "\(plan.linkPath) already points elsewhere. Replace it so it points at sinete, or keep the existing one? If you keep it, sinete isn't added to PATH and won't remove it on uninstall."
                    alert.addButton(withTitle: "Replace")
                    alert.addButton(withTitle: "Keep existing")
                    alert.addButton(withTitle: "Cancel")
                    switch alert.runModal() {
                    case .alertFirstButtonReturn: return 0
                    case .alertSecondButtonReturn: return 1
                    default: return 2
                    }
                }
                switch choice {
                case 0: args.append("--replace-link")
                case 1: args.append("--skip-link")
                default:
                    DispatchQueue.main.async { busy = false }
                    return
                }
            }
            var failure: String?
            do { try Backend.run(args) } catch { failure = error.localizedDescription }
            DispatchQueue.main.async {
                busy = false
                if let failure { reportError(failure); return }
                step = (status?.keyCount ?? 0) == 0 ? 1 : 2
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
            alert.informativeText = "\(pub) already exists. Overwrite it? If you keep it, sinete leaves it as is and won't remove it on uninstall."
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
            do { try Backend.run(["ssh-setup", name]) } catch { failure = error.localizedDescription }
            DispatchQueue.main.async {
                busy = false
                if let failure { reportError(failure); return }
                onDone()
            }
        }
    }
}
