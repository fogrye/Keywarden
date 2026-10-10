import AppKit
import ServiceManagement
import SwiftUI

enum SettingsTab: Hashable, CaseIterable { case security, preferences, browsers, app }

struct SettingsView: View {
    @Bindable var settings: AppSettings
    @Bindable var model: VaultModel
    @State var tab: SettingsTab = .security
    var scanner: BrowserScanner = .shared

    var body: some View {
        TabView(selection: $tab) {
            Tab("Security", image: "ShieldKey", value: .security) {
                SecuritySettings(settings: settings, model: model)
            }
            Tab("Preferences", systemImage: "slider.horizontal.3", value: .preferences) {
                PreferenceSettings(settings: settings)
            }
            Tab("Browsers", systemImage: "puzzlepiece.extension", value: .browsers) {
                BrowserSettings(model: model, scanner: scanner)
            }
            Tab("App", systemImage: "menubar.rectangle", value: SettingsTab.app) {
                AppLevelSettings(settings: settings)
            }
        }
        .frame(width: 560)
        .fixedSize(horizontal: false, vertical: true)
        // Start looking for browsers as soon as Settings opens, before the Browsers tab is chosen.
        .task { scanner.refreshIfIdle() }
        .alert("Keywarden", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
    }
}

// MARK: - Security

extension View {
    /// Disables a settings row and dims it: in a grouped form a disabled switch keeps its colour,
    /// so without this a locked vault's options would look changeable.
    func unavailable(_ unavailable: Bool) -> some View {
        disabled(unavailable).opacity(unavailable ? 0.45 : 1)
    }
}

private struct SecuritySettings: View {
    @Bindable var settings: AppSettings
    @Bindable var model: VaultModel
    @State private var changingEnrollment = false
    @State private var settingPin = false

    var body: some View {
        Form {
            Section {
                Picker("Timeout", selection: $settings.vaultTimeout) {
                    ForEach(VaultTimeout.choices, id: \.self) { choice in
                        Text(choice.title).tag(choice)
                    }
                }
                Picker("Timeout action", selection: $settings.timeoutAction) {
                    ForEach(TimeoutAction.allCases) { Text($0.title).tag($0) }
                }
                if settings.vaultTimeout.inactivityMinutes != nil {
                    Toggle("Also when the Mac locks or sleeps", isOn: $settings.lockOnSystemLock)
                        .unavailable(locked)
                }
                Toggle("When the vault window closes", isOn: $settings.lockOnWindowClose)
                    .accessibilityIdentifier("lockOnWindowClose")
                    .unavailable(locked)
            } header: {
                Text("Session Timeout")
            } footer: {
                Text(timeoutFooter)
            }
            // Someone at a locked Mac must not be able to loosen how the vault protects itself.
            .disabled(locked)

            Section {
                Toggle(isOn: Binding(get: { model.pinEnabled }, set: { enabled in
                    if enabled { settingPin = true } else { Task { await model.disablePin() } }
                })) {
                    Text("Unlock with PIN")
                    Text("Unlocks this Mac without your master password. Five wrong PINs turn it off.")
                }
                .unavailable(model.phase != .unlocked)

                Toggle(isOn: Binding(get: { model.biometricEnabled }, set: { enabled in
                    changingEnrollment = true
                    Task {
                        if enabled { await model.enableBiometrics() } else { await model.disableBiometrics() }
                        changingEnrollment = false
                    }
                })) {
                    Text("Unlock with Touch ID")
                    Text("Asked for automatically when the vault is locked. Also required for browser unlock.")
                }
                .disabled(changingEnrollment)
                .unavailable(model.phase != .unlocked)

            } header: {
                Text("Unlock Options")
            } footer: {
                if locked {
                    Text("Unlock the vault to change security settings.")
                } else if model.phase != .unlocked {
                    Text("Sign in to turn on unlock options.")
                } else if !model.email.isEmpty {
                    Text("Account: \(model.email)")
                }
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $settingPin) {
            PinSheet { pin in await model.enablePin(pin) }
        }
    }

    private var locked: Bool { model.phase == .locked }

    private var timeoutFooter: String {
        let action = settings.timeoutAction == .lock
            ? String(localized: "Locking keeps your account signed in; unlock with your master password, PIN or Touch ID.")
            : String(localized: "Logging out removes the account from this Mac; signing back in needs your master password and a connection.")
        switch settings.vaultTimeout {
        case .onRestart: return String(localized: "The vault stays unlocked until Keywarden quits. \(action)")
        default: return action
        }
    }
}

private struct PinSheet: View {
    let save: (String) async -> Bool
    @State private var pin = ""
    @State private var confirmation = ""
    @State private var saving = false
    @Environment(\.dismiss) private var dismiss

    private var valid: Bool { pin.count >= 4 && pin == confirmation }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Set a PIN").font(.headline)
            Text("Your PIN unlocks Keywarden on this Mac only. It is never sent to the server.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            SecureField("PIN", text: $pin)
            SecureField("Confirm PIN", text: $confirmation)
                .onSubmit(submit)
            if !confirmation.isEmpty && pin != confirmation {
                Text("PINs don’t match.").font(.caption).foregroundStyle(.red)
            } else if !pin.isEmpty && pin.count < 4 {
                Text("Use at least 4 characters.").font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Set PIN", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!valid || saving)
            }
        }
        .textFieldStyle(.roundedBorder)
        .padding(20)
        .frame(width: 340)
    }

    private func submit() {
        guard valid, !saving else { return }
        saving = true
        Task {
            if await save(pin) { dismiss() }
            saving = false
        }
    }
}

// MARK: - Preferences

private struct PreferenceSettings: View {
    @Bindable var settings: AppSettings

    var body: some View {
        Form {
            Section {
                Picker(selection: $settings.clearClipboardSeconds) {
                    ForEach(AppSettings.clipboardChoices, id: \.seconds) { choice in
                        Text(choice.title).tag(choice.seconds)
                    }
                } label: {
                    Text("Clear clipboard")
                    Text("Automatically clear copied values from your clipboard.")
                }
                Toggle(isOn: $settings.minimizeOnCopy) {
                    Text("Minimize when copying to clipboard")
                    Text("Hide Keywarden when copying an item’s data, returning to the app you were using.")
                }
            }
            Section {
                Toggle(isOn: $settings.showWebsiteIcons) {
                    Text("Show website icons")
                    Text("Loads each login’s icon from your server’s icon service. Only the website’s domain is sent.")
                }
            }
        }
        .formStyle(.grouped)
    }
}

// MARK: - Browsers

private struct BrowserSettings: View {
    @Bindable var model: VaultModel
    let scanner: BrowserScanner
    @State private var confirming: Pending?
    @State private var failure: String?
    @State private var changingUnlock = false
    @State private var changing = false

    private var browsers: [Installer.BrowserStatus] { scanner.scan?.browsers ?? [] }

    private struct Pending: Identifiable {
        enum Action { case connect, replace, disconnect }
        let action: Action
        let status: Installer.BrowserStatus
        var id: String { status.id }
    }

    var body: some View {
        Form {
            Section {
                Toggle(isOn: Binding(get: { model.browserBiometricsEnabled }, set: { enabled in
                    guard enabled else { model.setBrowserBiometricsEnabled(false); return }
                    changingUnlock = true
                    Task {
                        await model.enableBrowserBiometrics()
                        changingUnlock = false
                    }
                })) {
                    Text("Unlock browsers with Touch ID")
                    Text("The Bitwarden extension asks this app, which confirms with Touch ID and hands over the key for the same account.")
                }
                .disabled(changingUnlock)
                .unavailable(model.phase != .unlocked)
                .accessibilityIdentifier("browserUnlock")
            } header: {
                Text("Touch ID in Browsers")
            } footer: {
                if model.phase == .locked {
                    Text("Unlock the vault to change this.")
                } else if model.phase != .unlocked {
                    Text("Sign in to turn this on.")
                } else if !model.browserBiometricsEnabled {
                    Text(model.biometricEnabled ? "Turn this on, then connect your browsers below."
                         : "Turning this on also sets up Touch ID unlock for this app.")
                } else {
                    Text("In the Bitwarden extension, sign in to the same account, then turn on “Unlock with biometrics”.")
                }
            }

            Section {
                if let scan = scanner.scan {
                    if scan.browsers.isEmpty {
                        Text("No supported browser was found.").foregroundStyle(.secondary)
                    }
                    ForEach(scan.browsers) { status in row(status) }
                    if scan.outdated || scan.elsewhere {
                        HStack {
                            Label(scan.outdated ? "Connected browsers launch an older build of this app."
                                                : "Connected browsers launch another copy of this app.",
                                  systemImage: "arrow.triangle.2.circlepath")
                                .foregroundStyle(.secondary)
                            Spacer()
                            Button(scan.outdated ? "Update" : "Use This Copy") { run { try Installer.updateConnections() } }
                                .disabled(changing)
                        }
                    }
                } else {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Looking for browsers…").foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("browserScanProgress")
                }
                if let failure {
                    Label(failure, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            } header: {
                HStack {
                    Text("Browsers")
                    Spacer()
                    // A rescan behind a list already shown, or a connection change in progress.
                    if changing || (scanner.isScanning && scanner.scan != nil) {
                        ProgressView().controlSize(.mini)
                    }
                }
            } footer: {
                if !model.browserBiometricsEnabled, browsers.contains(where: { if case .this = $0.registration { false } else { true } }) {
                    Text("Turn on Touch ID in browsers above to connect a browser.")
                }
                Text("Works with the official Bitwarden extension in Firefox-based browsers (Firefox, Zen) and Chromium-based ones (Chrome, Edge, Brave, Arc, Vivaldi, Opera). A browser’s previous connection is saved and restored when you disconnect it.")
            }
        }
        .formStyle(.grouped)
        .onAppear(perform: refresh)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in refresh() }
        .confirmationDialog(title(confirming), isPresented: Binding(get: { confirming != nil },
                                                                   set: { if !$0 { confirming = nil } }),
                            presenting: confirming) { pending in
            Button(buttonTitle(pending.action), role: pending.action == .connect ? nil : .destructive) {
                perform(pending)
            }
        } message: { pending in
            Text(message(pending))
        }
    }

    private func row(_ status: Installer.BrowserStatus) -> some View {
        HStack(spacing: 10) {
            Group {
                if let app = status.app {
                    Image(nsImage: scanner.icon(for: app))
                        .resizable()
                } else {
                    Image(systemName: "globe").resizable().scaledToFit().foregroundStyle(.secondary)
                }
            }
            .frame(width: 26, height: 26)
            VStack(alignment: .leading, spacing: 2) {
                Text(status.browser.name)
                HStack(spacing: 5) {
                    Circle().fill(color(status)).frame(width: 7, height: 7)
                    Text(detail(status))
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            switch status.registration {
            case .none:
                Button("Connect") { confirming = Pending(action: .connect, status: status) }
                    .disabled(changing || !status.verifiable || status.app == nil || !model.browserBiometricsEnabled)
            case .other:
                Button("Replace…") { confirming = Pending(action: .replace, status: status) }
                    .disabled(changing || !status.verifiable || status.app == nil || !model.browserBiometricsEnabled)
            case .this:
                Button("Disconnect…") { confirming = Pending(action: .disconnect, status: status) }
                    .disabled(changing)
            }
        }
        .padding(.vertical, 2)
    }

    private func detail(_ status: Installer.BrowserStatus) -> String {
        if status.app == nil { return String(localized: "Not installed — still connected") }
        if !status.verifiable { return String(localized: "Signature can’t be verified") }
        if status.browser.family == .firefox, status.browser.id != "firefox",
           browsers.contains(where: { $0.browser.id == "firefox" && $0.registration != .none }) {
            // Forks read Mozilla's shared registration first, so Firefox's connection decides.
            if case .this = browsers.first(where: { $0.browser.id == "firefox" })?.registration {
                return String(localized: "Connected through Firefox’s registration")
            }
            return String(localized: "Uses Firefox’s registration, which belongs to another app")
        }
        switch status.registration {
        case .none: return String(localized: "Not connected")
        case .this: return String(localized: "Connected")
        case .other(let path):
            return path.contains("/Bitwarden.app/") ? String(localized: "Used by Bitwarden Desktop")
                : String(localized: "Used by another app")
        }
    }

    private func color(_ status: Installer.BrowserStatus) -> Color {
        switch status.registration {
        case .this: .green
        case .other: .orange
        case .none: .secondary
        }
    }

    private func title(_ pending: Pending?) -> String {
        guard let pending else { return "" }
        let name = pending.status.browser.name
        return switch pending.action {
        case .connect: String(localized: "Connect \(name) to this app?")
        case .replace: String(localized: "Replace \(name)’s existing connection?")
        case .disconnect: String(localized: "Disconnect \(name)?")
        }
    }

    private func buttonTitle(_ action: Pending.Action) -> String {
        switch action {
        case .connect: String(localized: "Connect")
        case .replace: String(localized: "Replace")
        case .disconnect: String(localized: "Disconnect")
        }
    }

    private func message(_ pending: Pending) -> String {
        let name = pending.status.browser.name
        switch pending.action {
        case .connect:
            return String(localized: "\(name) will ask this app for Touch ID unlock through the official Bitwarden extension.")
        case .replace:
            if case .other(let path) = pending.status.registration {
                return String(localized: "\(name) is registered with \(path). That registration is saved and restored if you disconnect.")
            }
            return ""
        case .disconnect:
            return pending.status.hasBackup
                ? String(localized: "\(name)’s previous connection is restored. Touch ID enrollment stays on this Mac.")
                : String(localized: "\(name) will no longer reach this app. Touch ID enrollment stays on this Mac.")
        }
    }

    private func refresh() { scanner.refreshIfIdle() }

    private func perform(_ pending: Pending) {
        let browser = pending.status.browser
        run {
            switch pending.action {
            case .connect: try Installer.connect(browser, replace: false)
            case .replace: try Installer.connect(browser, replace: true)
            case .disconnect: try Installer.disconnect(browser)
            }
        }
    }

    /// Connection changes verify signatures and may copy the app, so they run off the main thread.
    private func run(_ operation: @escaping @Sendable () throws -> Void) {
        failure = nil
        changing = true
        Task {
            failure = await scanner.change(operation)
            changing = false
        }
    }
}

// MARK: - App

private struct AppLevelSettings: View {
    @Bindable var settings: AppSettings
    @State private var openAtLogin = SMAppService.mainApp.status == .enabled
    @State private var loginItemError: String?

    var body: some View {
        Form {
            Section {
                Picker(selection: $settings.iconPlacement) {
                    ForEach(AppIconPlacement.allCases) { Text($0.title).tag($0) }
                } label: {
                    Text("Show Keywarden in")
                    Text("With the menu bar alone, the Dock icon appears only while a Keywarden window is open.")
                }
                Toggle(isOn: $settings.keepRunningInBackground) {
                    Text("Keep Keywarden running in the background")
                    Text("When you close the window, Keywarden keeps running. Recommended for browser integration.")
                }
                Toggle(isOn: Binding(get: { openAtLogin }, set: setOpenAtLogin)) {
                    Text("Start automatically on login")
                    Text("Start Keywarden in the background when you log in.")
                }
                if let loginItemError {
                    Text(loginItemError).font(.caption).foregroundStyle(.red)
                }
            }
            Section {
                LabeledContent("Version", value: Self.version)
                LabeledContent("Location") {
                    Text(Bundle.main.bundleURL.deletingLastPathComponent().path)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { openAtLogin = SMAppService.mainApp.status == .enabled }
    }

    private static var version: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "?"
        let build = info["CFBundleVersion"] as? String ?? "?"
        #if DEBUG
        return "\(version) (\(build), debug)"
        #else
        return "\(version) (\(build))"
        #endif
    }

    private func setOpenAtLogin(_ enabled: Bool) {
        loginItemError = nil
        do {
            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            loginItemError = error.localizedDescription
        }
        let status = SMAppService.mainApp.status
        openAtLogin = status == .enabled
        if status == .requiresApproval {
            loginItemError = String(localized: "Allow Keywarden in System Settings › General › Login Items.")
            SMAppService.openSystemSettingsLoginItems()
        }
    }
}
