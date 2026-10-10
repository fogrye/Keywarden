import AppKit
import Carbon.HIToolbox
import SwiftUI

struct LoginView: View {
    @Bindable var model: VaultModel
    @FocusState private var focus: Field?
    @State private var region = ServerRegion.us
    @State private var useMasterPassword = false
    @State private var pin = ""
    /// Touch ID is being asked for; the PIN or password field is disabled meanwhile.
    @State private var askingTouchID = false
    /// The PIN or password field waits, disabled, for a hotkey's keys to be let go before it
    /// takes focus and turns on Secure Input.
    @State private var waitingForKeys = true
    @State private var focusTask: Task<Void, Never>?
    @State private var touchIDTask: Task<Void, Never>?
    @State private var isActive = true

    private enum Field { case email, server, password }
    private var locked: Bool { model.phase == .locked }
    private var usesPin: Bool { locked && model.pinEnabled && !useMasterPassword }

    var body: some View {
        VStack(spacing: 18) {
            if locked {
                Image("MenuBarLocked")
                    .resizable()
                    .frame(width: 56, height: 56)
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
            } else {
                // From the bundle, not NSApp.applicationIconImage: that goes through the system icon
                // cache, which can still hold an older icon after an update.
                Image(nsImage: NSImage(named: "AppIcon") ?? NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 72, height: 72)
                    .accessibilityHidden(true)
            }
            VStack(spacing: 4) {
                Text(locked ? "Vault Locked" : "Welcome to Keywarden")
                    .font(.title2.weight(.semibold))
                (locked ? Text(verbatim: "\(model.email) · \(ServerRegion.displayHost(model.server))")
                        : Text("Sign in with your Bitwarden-compatible account."))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            VStack(spacing: 10) {
                if !locked {
                    if region == .selfHosted {
                        TextField("Server URL", text: $model.server, prompt: Text("https://vault.example.com"))
                            .focused($focus, equals: .server)
                            .onSubmit { focusPassword(model.email.isEmpty ? .email : .password) }
                            .accessibilityLabel("Account server")
                    }
                    TextField("Email", text: $model.email)
                        .textContentType(.username)
                        .focused($focus, equals: .email)
                        .onSubmit { focusPassword() }
                        .accessibilityLabel("Account email")
                }
                if usesPin {
                    SecureField("PIN", text: $pin)
                        .focused($focus, equals: .password)
                        .disabled(askingTouchID || waitingForKeys)
                        .onSubmit(submit)
                        .accessibilityLabel("PIN")
                } else {
                    SecureField("Master password", text: $model.password)
                        .textContentType(.password)
                        .focused($focus, equals: .password)
                        .disabled((askingTouchID && locked) || waitingForKeys)
                        .onSubmit(submit)
                        .accessibilityLabel("Master password")
                }
            }
            .textFieldStyle(.roundedBorder)
            .controlSize(.large)

            Button(action: submit) {
                Group {
                    if model.isBusy {
                        ProgressView().controlSize(.small)
                    } else {
                        Text(locked ? "Unlock" : "Sign In")
                    }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .disabled(!canSubmit)
            .accessibilityLabel(locked ? "Unlock vault" : "Sign in to your vault")

            if locked && model.biometricEnabled {
                Button {
                    touchIDTask = Task { await askForTouchID() }
                } label: {
                    Label("Unlock with Touch ID", systemImage: "touchid").frame(maxWidth: .infinity)
                }
                .controlSize(.large)
                .disabled(model.isBusy || askingTouchID)
            }

            if locked {
                HStack {
                    if model.pinEnabled {
                        Button(useMasterPassword ? "Use PIN" : "Use master password") {
                            useMasterPassword.toggle()
                            focusPassword()
                        }
                        Spacer()
                    }
                    Button("Sign Out…") { Task { await model.logout() } }
                }
                .buttonStyle(.link)
                .font(.callout)
                .disabled(model.isBusy)
            } else {
                Picker("Server", selection: $region) {
                    ForEach(ServerRegion.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.menu)
                .fixedSize()
                .font(.callout)
                .disabled(model.isBusy)
                .accessibilityIdentifier("serverRegion")
            }
        }
        .frame(width: 320)
        .padding(32)
        .onChange(of: region) { _, region in
            if let server = region.server {
                model.server = server
            } else if ServerRegion(server: model.server) != .selfHosted {
                model.server = ""
                focus = .server
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear {
            region = ServerRegion(server: model.server)
            focusPassword(locked || !model.email.isEmpty ? .password : .email)
        }
        .onChange(of: model.phase) { _, phase in
            if phase != .locked {
                touchIDTask?.cancel()
                askingTouchID = false
            }
            if phase == .unlocked {
                focusTask?.cancel()
            } else {
                focusPassword(phase == .loggedOut && model.email.isEmpty ? .email : .password)
            }
            if phase == .loggedOut { region = ServerRegion(server: model.server) }
            pin = ""
        }
        .onChange(of: model.pinEnabled) { _, enabled in if !enabled { useMasterPassword = false } }
        .onDisappear {
            focusTask?.cancel()
            touchIDTask?.cancel()
        }
        // A field still focused when the app is reactivated by a hotkey would turn Secure Input
        // back on while the hotkey is held, so it is disabled while Keywarden is in the background.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            isActive = false
            focusTask?.cancel()
            waitingForKeys = true
            focus = nil
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            isActive = true
            if !askingTouchID { focusPassword(locked || !model.email.isEmpty ? .password : .email) }
        }
    }

    /// Focuses the PIN or password field once a launcher hotkey's keys (rcmd, Tinycast, a Hyper
    /// key) are let go. The field holds Secure Input, which hides key events from other apps'
    /// event taps: turned on mid-hotkey, the launcher or remapper never saw its keys released and
    /// kept them pressed, so typing, arrows and ⌘H went nowhere until the hotkey was pressed again.
    private func focusPassword(_ field: Field = .password) {
        focusTask?.cancel()
        waitingForKeys = true
        focus = nil
        guard isActive, !askingTouchID else { return }
        focusTask = Task {
            guard await Self.keysReleased(for: "Login field focused", secureInputOff: false),
                  !Task.isCancelled, isActive, !askingTouchID else { return }
            waitingForKeys = false
            focus = field
        }
    }

    /// Asks for Touch ID with the PIN or password field disabled, once a launcher hotkey's keys
    /// (Tinycast, Raycast) are let go. A field that can take focus holds Secure Input, which keeps
    /// the Touch ID panel from coming to the front: modifiers released then reached no app and stayed
    /// pressed for the whole system, so typing and ⌘Q went nowhere until the hotkey was pressed again.
    /// Releasing focus alone wasn't enough, because SwiftUI gave it straight back to the field.
    private func askForTouchID() async {
        guard !askingTouchID else { return }
        askingTouchID = true
        focusTask?.cancel()
        waitingForKeys = true
        focus = nil
        NSApp.keyWindow?.makeFirstResponder(nil)
        // Not when the wait was cancelled: the lock screen has gone away meanwhile.
        if await Self.keysReleased(for: "Touch ID asked", secureInputOff: true),
           !Task.isCancelled, locked {
            await model.unlockBiometrics()
        }
        askingTouchID = false
        if !Task.isCancelled, model.phase != .unlocked { focusPassword() }
    }

    /// Waits for every physical and remapped key to stay released for 100 ms, with no timeout
    /// that could enable Secure Input mid-hotkey. False if the owning view cancels the wait.
    private static func keysReleased(for purpose: String, secureInputOff: Bool) async -> Bool {
        let start = Date()
        var releasedAt: ContinuousClock.Instant?
        while !Task.isCancelled {
            let held = keysHeld()
            let secure = secureInputOff && IsSecureEventInputEnabled()
            if held || secure {
                releasedAt = nil
            } else if let releasedAt {
                if releasedAt.duration(to: .now) >= .milliseconds(100) {
                    let waited = Int(Date().timeIntervalSince(start) * 1000)
                    biometricLog.notice("\(purpose, privacy: .public) after \(waited) ms")
                    return true
                }
            } else {
                releasedAt = .now
            }
            do { try await Task.sleep(for: .milliseconds(25)) } catch { return false }
        }
        return false
    }

    /// Check both hardware and session state: remappers can post keys that aren't physically
    /// held, and AppKit only knows events sent to this app. Never record which keys are held.
    static var keysHeld: () -> Bool = {
        let modifiers: CGEventFlags = [.maskCommand, .maskAlternate, .maskControl, .maskShift]
        if !CGEventSource.flagsState(.hidSystemState).isDisjoint(with: modifiers)
            || !CGEventSource.flagsState(.combinedSessionState).isDisjoint(with: modifiers) { return true }
        for key: CGKeyCode in 0..<128 {
            if keyIsDown(.hidSystemState, key) || keyIsDown(.combinedSessionState, key) { return true }
        }
        return false
    }

    static var keyIsDown: (CGEventSourceStateID, CGKeyCode) -> Bool = {
        CGEventSource.keyState($0, key: $1)
    }

    private var canSubmit: Bool {
        if usesPin { return !model.isBusy && !pin.isEmpty }
        if locked { return !model.isBusy && !model.password.isEmpty }
        let serverChosen = region != .selfHosted || !model.server.trimmingCharacters(in: .whitespaces).isEmpty
        return !model.isBusy && !model.password.isEmpty && !model.email.isEmpty && serverChosen
    }

    private func submit() {
        guard canSubmit else { return }
        let entered = pin
        pin = ""
        Task {
            if usesPin { await model.unlock(pin: entered) }
            else if locked { await model.unlock() }
            else { await model.login() }
            if model.phase != .unlocked { focusPassword() }
        }
    }
}

/// Where the account lives: one of Bitwarden's cloud regions, or a self-hosted server
/// compatible with Bitwarden. The cloud regions map to the addresses `Endpoints::parse` knows.
enum ServerRegion: String, CaseIterable, Identifiable {
    case us, eu, selfHosted

    var id: Self { self }

    var title: String {
        switch self {
        case .us: "bitwarden.com"
        case .eu: "bitwarden.eu"
        case .selfHosted: String(localized: "Self-hosted")
        }
    }

    /// The address to sign in with, or nil when the user types it.
    var server: String? {
        switch self {
        case .us: ""
        case .eu: "https://bitwarden.eu"
        case .selfHosted: nil
        }
    }

    /// Infers the region from a sign-in address or a stored account's API address.
    init(server: String) {
        let trimmed = server.trimmingCharacters(in: .whitespaces).lowercased()
        let host = URL(string: trimmed)?.host() ?? trimmed
        switch host {
        case "", "bitwarden.com", "vault.bitwarden.com", "api.bitwarden.com": self = .us
        case "bitwarden.eu", "vault.bitwarden.eu", "api.bitwarden.eu": self = .eu
        default: self = .selfHosted
        }
    }

    /// A short name for the account's server, e.g. "bitwarden.eu" or "vault.example.com".
    static func displayHost(_ server: String) -> String {
        switch ServerRegion(server: server) {
        case .selfHosted: URL(string: server)?.host() ?? server
        case let region: region.title
        }
    }
}
