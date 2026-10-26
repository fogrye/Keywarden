import AppKit
import SwiftUI

struct LoginView: View {
    @Bindable var model: VaultModel
    /// Ask for Touch ID by itself when the lock screen is brought to the front.
    var autoTouchID = false
    @FocusState private var focus: Field?
    @State private var region = ServerRegion.us
    @State private var useMasterPassword = false
    @State private var pin = ""
    /// Touch ID is being asked for; the PIN or password field is disabled meanwhile.
    @State private var askingTouchID = false
    @State private var touchIDTask: Task<Void, Never>?
    /// The next time the lock screen is in front may ask for Touch ID by itself.
    @State private var promptArmed: Bool
    @State private var focusOwner = LoginFocusOwner()

    init(model: VaultModel, autoTouchID: Bool = false) {
        self.model = model
        self.autoTouchID = autoTouchID
        // Starting locked counts as being brought to the front; locking in front of the user doesn't.
        _promptArmed = State(initialValue: !model.lockedAfterUse)
    }

    private enum Field { case email, server, password, pin }
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
                            .onSubmit { selectField(model.email.isEmpty ? .email : .password) }
                            .accessibilityLabel("Account server")
                    }
                    TextField("Email", text: $model.email)
                        .textContentType(.username)
                        .focused($focus, equals: .email)
                        .onSubmit { selectField(.password) }
                        .accessibilityLabel("Account email")
                }
                if usesPin {
                    SecureField("PIN", text: $pin)
                        .focused($focus, equals: .pin)
                        .disabled(askingTouchID || !focusOwner.isEligible)
                        .onSubmit(submit)
                        .accessibilityLabel("PIN")
                } else {
                    SecureField("Master password", text: $model.password)
                        .textContentType(.password)
                        .focused($focus, equals: .password)
                        .disabled(askingTouchID || !focusOwner.isEligible)
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
                .disabled(model.isBusy || askingTouchID || !focusOwner.isEligible)
            }

            if locked {
                HStack {
                    if model.pinEnabled {
                        Button(useMasterPassword ? "Use PIN" : "Use master password") {
                            useMasterPassword.toggle()
                            selectField(usesPin ? .pin : .password)
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
        .background(LoginFocusAnchor(owner: focusOwner, clearFocus: { focus = nil }, interrupted: {
            touchIDTask?.cancel()
        }).accessibilityHidden(true))
        .onAppear {
            region = ServerRegion(server: model.server)
            focus = nil
        }
        .onChange(of: model.phase) { _, phase in
            if phase != .locked {
                touchIDTask?.cancel()
                askingTouchID = false
            }
            focus = nil
            focusOwner.parkFocus()
            if phase == .loggedOut { region = ServerRegion(server: model.server) }
            pin = ""
            askAutomatically()
        }
        // Leaving the front arms the automatic prompt for the next return. The Touch ID prompt itself
        // takes the front from Keywarden; that doesn't count.
        .onChange(of: focusOwner.isInFront) { _, inFront in
            if !inFront && !askingTouchID { promptArmed = true }
            askAutomatically()
        }
        .onChange(of: focusOwner.isEligible) { askAutomatically() }
        .onChange(of: model.biometricEnabled) { askAutomatically() }
        .onChange(of: model.isBusy) { askAutomatically() }
        .onChange(of: autoTouchID) { askAutomatically() }
        .onChange(of: model.pinEnabled) { _, enabled in if !enabled { useMasterPassword = false } }
        // Not `focusOwner.detach()`: closing the window makes this disappear, but reopening it shows
        // the same view again without moving it to a window, so nothing would attach it.
        .onDisappear { touchIDTask?.cancel() }
    }

    private func selectField(_ field: Field) {
        guard focusOwner.isEligible, !askingTouchID else { return }
        focus = field
    }

    /// Asks for Touch ID once the lock screen has been brought to the front: opened, or returned to
    /// from another app, a closed window or the Dock. Never because the vault locked in front of the user.
    private func askAutomatically() {
        guard autoTouchID, promptArmed, locked, model.biometricEnabled, !model.isBusy, !askingTouchID,
              focusOwner.isEligible else { return }
        promptArmed = false
        touchIDTask = Task { await askForTouchID() }
    }

    private func askForTouchID() async {
        guard locked, focusOwner.isEligible, !model.isBusy, !askingTouchID else { return }
        askingTouchID = true
        focus = nil
        defer {
            askingTouchID = false
            if locked { focus = nil; focusOwner.parkFocus() }
        }
        guard await focusOwner.prepareForBiometrics() else {
            if !Task.isCancelled, focusOwner.isEligible {
                model.errorMessage = String(localized: "Could not leave the password field. Try again.")
            }
            return
        }
        guard !Task.isCancelled, locked, focusOwner.isEligible else { return }
        await model.unlockBiometrics()
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
        }
    }
}

/// Secure entry belongs to this window's first responder, never global keyboard state.
@MainActor @Observable private final class LoginFocusOwner {
    private(set) var isEligible = false
    /// Keywarden is active with this window on screen. Its own sheets or other windows taking key
    /// don't take it out of the front. Assumed until measured, so a lock screen that replaces the
    /// vault in a window already in front doesn't count as arriving there.
    private(set) var isInFront = true
    @ObservationIgnored private weak var window: NSWindow?
    @ObservationIgnored private weak var anchor: NSView?
    @ObservationIgnored private weak var previousInitialResponder: NSView?
    @ObservationIgnored private var observers: [NSObjectProtocol] = []
    @ObservationIgnored private var generation = 0
    @ObservationIgnored var clearFocus: (() -> Void)?
    @ObservationIgnored var interrupted: (() -> Void)?

    func attach(_ view: NSView) {
        guard window !== view.window || anchor !== view else { return }
        detach()
        guard let window = view.window else { return }
        generation += 1
        self.window = window
        anchor = view
        previousInitialResponder = window.initialFirstResponder
        window.initialFirstResponder = view
        parkFocus()
        let center = NotificationCenter.default
        for name in [NSWindow.didBecomeKeyNotification, NSWindow.didResignKeyNotification,
                     NSWindow.didMiniaturizeNotification, NSWindow.didDeminiaturizeNotification,
                     NSWindow.willCloseNotification] {
            observers.append(center.addObserver(forName: name, object: window, queue: .main) { [weak self] notification in
                let closing = notification.name == NSWindow.willCloseNotification
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.clearFocus?()
                    // A closed window comes back with this view still in it, so keep watching it.
                    if closing { self.interrupted?() }
                    self.parkFocus()
                    self.refreshEligibility(resigning: closing)
                }
            })
        }
        for name in [NSApplication.willResignActiveNotification, NSApplication.didResignActiveNotification,
                     NSApplication.didBecomeActiveNotification] {
            observers.append(center.addObserver(forName: name, object: NSApp, queue: .main) { [weak self] notification in
                let resigning = notification.name == NSApplication.willResignActiveNotification
                MainActor.assumeIsolated {
                    guard let self else { return }
                    self.clearFocus?()
                    self.parkFocus()
                    self.refreshEligibility(resigning: resigning)
                }
            })
        }
        // Attachment runs inside SwiftUI rendering. Native focus is released immediately;
        // observable eligibility and FocusState are published on the next main turn.
        let attachedGeneration = generation
        DispatchQueue.main.async { [weak self] in
            guard let self, self.generation == attachedGeneration, self.anchor === view else { return }
            self.clearFocus?()
            self.parkFocus()
            self.refreshEligibility()
        }
    }

    private func refreshEligibility(resigning: Bool = false) {
        isInFront = !resigning && NSApp.isActive && window?.isVisible == true
            && window?.isMiniaturized == false && anchor?.window === window
        isEligible = isInFront && window?.isKeyWindow == true
    }

    @discardableResult func parkFocus() -> Bool {
        guard let window, let anchor, anchor.window === window else { return false }
        return window.makeFirstResponder(anchor) && window.firstResponder === anchor
    }

    func prepareForBiometrics() async -> Bool {
        guard !Task.isCancelled, isEligible, parkFocus() else { return false }
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
        guard !Task.isCancelled, isEligible, let window, let anchor, anchor.window === window else { return false }
        return !((window.firstResponder as? NSTextView)?.delegate is NSSecureTextField)
    }

    func detach() {
        generation += 1
        for observer in observers { NotificationCenter.default.removeObserver(observer) }
        observers.removeAll()
        if let window, let anchor, window.initialFirstResponder === anchor {
            parkFocus()
            window.initialFirstResponder = previousInitialResponder
        }
        window = nil
        anchor = nil
        previousInitialResponder = nil
        // Detachment can happen during a view update as well.
        let detachedGeneration = generation
        DispatchQueue.main.async { [weak self] in
            guard let self, self.generation == detachedGeneration else { return }
            self.isEligible = false
            self.isInFront = false
            self.clearFocus?()
            self.interrupted?()
            self.clearFocus = nil
            self.interrupted = nil
        }
    }

    isolated deinit {
        for observer in observers { NotificationCenter.default.removeObserver(observer) }
    }
}

private struct LoginFocusAnchor: NSViewRepresentable {
    let owner: LoginFocusOwner
    let clearFocus: () -> Void
    let interrupted: () -> Void

    func makeNSView(context: Context) -> Anchor {
        owner.clearFocus = clearFocus
        owner.interrupted = interrupted
        return Anchor(owner: owner)
    }

    func updateNSView(_ view: Anchor, context: Context) {
        owner.clearFocus = clearFocus
        owner.interrupted = interrupted
    }

    static func dismantleNSView(_ view: Anchor, coordinator: ()) { view.owner.detach() }

    final class Anchor: NSView {
        let owner: LoginFocusOwner
        init(owner: LoginFocusOwner) {
            self.owner = owner
            super.init(frame: .zero)
            setAccessibilityElement(false)
        }
        required init?(coder: NSCoder) { nil }
        override var acceptsFirstResponder: Bool { true }
        override var canBecomeKeyView: Bool { false }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            owner.attach(self)
        }
        override func insertTab(_ sender: Any?) { window?.selectNextKeyView(self) }
        override func insertBacktab(_ sender: Any?) { window?.selectPreviousKeyView(self) }
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
