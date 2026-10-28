import Foundation
import CoreFoundation
import CryptoKit
import Observation
import os

/// When the vault locks (or signs out) on its own.
enum VaultTimeout: Hashable, Sendable {
    case minutes(Int), onSleep, onSystemLock, onRestart

    static let choices: [VaultTimeout] = [
        .minutes(1), .minutes(5), .minutes(15), .minutes(30), .minutes(60), .minutes(240),
        .onSleep, .onSystemLock, .onRestart,
    ]

    var title: String {
        switch self {
        case .minutes(let minutes): Duration.seconds(minutes * 60).spelledOut
        case .onSleep: String(localized: "On system sleep")
        case .onSystemLock: String(localized: "On system lock")
        case .onRestart: String(localized: "On restart")
        }
    }

    fileprivate var stored: String {
        switch self {
        case .minutes(let minutes): String(minutes)
        case .onSleep: "onSleep"
        case .onSystemLock: "onSystemLock"
        case .onRestart: "onRestart"
        }
    }

    fileprivate init?(stored: String) {
        switch stored {
        case "onSleep": self = .onSleep
        case "onSystemLock": self = .onSystemLock
        case "onRestart": self = .onRestart
        default:
            guard let minutes = Int(stored), minutes > 0 else { return nil }
            self = .minutes(minutes)
        }
    }

    var inactivityMinutes: Int? {
        if case .minutes(let minutes) = self { return minutes }
        return nil
    }
}

/// Where Keywarden shows its icon while it runs.
enum AppIconPlacement: String, CaseIterable, Identifiable, Sendable {
    case menuBar, dock, both
    var id: Self { self }
    var title: String {
        switch self {
        case .menuBar: String(localized: "Menu bar")
        case .dock: String(localized: "Dock")
        case .both: String(localized: "Menu bar and Dock")
        }
    }
    var showsMenuBarIcon: Bool { self != .dock }
    var showsDockIcon: Bool { self != .menuBar }
}

enum TimeoutAction: String, CaseIterable, Identifiable, Sendable {
    case lock, logOut
    var id: Self { self }
    var title: String { self == .lock ? String(localized: "Lock") : String(localized: "Log out") }
}

/// Where the security settings live. UserDefaults can be rewritten by any process running as the
/// user, which would let malware stretch the timeout or stop clipboard clearing without unlocking,
/// so the app keeps them in its own Keychain access group instead. Tests pass `memory()`.
struct SecuritySettingsStore {
    var load: () throws -> Data?
    var save: (Data) throws -> Void

    static var keychain: SecuritySettingsStore {
        let account = SHA256.hash(data: Data("keywarden.settings.security".utf8))
            .map { String(format: "%02x", $0) }.joined()
        return SecuritySettingsStore(
            load: { try PlatformCredentials.read(PlatformCredentials.settings, account) },
            save: { try PlatformCredentials.store($0, service: PlatformCredentials.settings, account: account) })
    }

    static func memory(_ initial: Data? = nil) -> SecuritySettingsStore {
        final class Box: @unchecked Sendable { var data: Data? }
        let box = Box()
        box.data = initial
        return SecuritySettingsStore(load: { box.data }, save: { box.data = $0 })
    }
}

/// The stored form of the security settings. Values are checked again when loaded.
private struct SecuritySnapshot: Codable {
    var vaultTimeout: String
    var timeoutAction: String
    var lockOnSystemLock: Bool
    var lockOnWindowClose: Bool
    var clearClipboardSeconds: Int
}

private let settingsLog = Logger(subsystem: "xyz.kuvshynov.Keywarden", category: "core")

@MainActor @Observable
final class AppSettings {
    static let clipboardChoices: [(seconds: Int, title: String)] = [
        (0, String(localized: "Never")),
    ] + [10, 20, 30, 60, 120, 300].map { ($0, Duration.seconds($0).spelledOut) }

    static var accountDefaults: UserDefaults {
        #if DEBUG
        let environment = ProcessInfo.processInfo.environment
        if let namespace = environment["BW_TEST_NAMESPACE"] ?? environment["BW_UI_TEST_NAMESPACE"],
           UUID(uuidString: namespace) != nil,
           let defaults = UserDefaults(suiteName: "xyz.kuvshynov.Keywarden.test.\(namespace)") {
            return defaults
        }
        #endif
        return .standard
    }

    private let defaults: UserDefaults
    private let secure: SecuritySettingsStore
    /// False when the Keychain could not be read: the safe defaults apply for this session and
    /// nothing is written over the stored values.
    private let persistsSecurity: Bool
    var onChange: (() -> Void)?

    /// Keys earlier builds kept in UserDefaults. Read once, when the Keychain has no settings yet.
    private static let legacySecurityKeys = ["vaultTimeout", "vaultTimeoutMinutes", "timeoutAction",
                                             "lockOnSystemLock", "lockOnWindowClose", "clearClipboardSeconds"]

    // Security
    var vaultTimeout: VaultTimeout {
        didSet { saveSecurity(); onChange?() }
    }
    var timeoutAction: TimeoutAction {
        didSet { saveSecurity(); onChange?() }
    }
    /// With a minutes timeout, also lock when the Mac locks its screen or sleeps.
    var lockOnSystemLock: Bool {
        didSet { saveSecurity(); onChange?() }
    }
    var lockOnWindowClose: Bool {
        didSet { saveSecurity(); onChange?() }
    }

    // Preferences
    var clearClipboardSeconds: Int {
        didSet { saveSecurity() }
    }
    var minimizeOnCopy: Bool {
        didSet { defaults.set(minimizeOnCopy, forKey: "minimizeOnCopy") }
    }
    /// Ask for Touch ID as soon as the lock screen is in front, when it is set up.
    var autoTouchID: Bool {
        didSet { defaults.set(autoTouchID, forKey: "autoTouchID") }
    }
    var showWebsiteIcons: Bool {
        didSet {
            defaults.set(showWebsiteIcons, forKey: "showWebsiteIcons")
            if !showWebsiteIcons { WebsiteIcons.shared.clear() }
        }
    }

    // App
    var keepRunningInBackground: Bool {
        didSet { defaults.set(keepRunningInBackground, forKey: "keepRunningInBackground"); onAppearanceChange?() }
    }
    var iconPlacement: AppIconPlacement {
        didSet { defaults.set(iconPlacement.rawValue, forKey: "iconPlacement"); onAppearanceChange?() }
    }
    var onAppearanceChange: (() -> Void)?

    /// Bound to the menu bar extra. Removing the icon (⌘-dragging it out of the menu bar) moves
    /// Keywarden to the Dock, so there is always a way back to it.
    var showsMenuBarIcon: Bool {
        get { iconPlacement.showsMenuBarIcon }
        set {
            switch (newValue, iconPlacement) {
            case (false, .menuBar), (false, .both): iconPlacement = .dock
            case (true, .dock): iconPlacement = .both
            default: break
            }
        }
    }

    init(defaults: UserDefaults? = nil, secure: SecuritySettingsStore = .keychain) {
        let defaults = defaults ?? Self.accountDefaults
        self.defaults = defaults
        self.secure = secure
        let snapshot: SecuritySnapshot
        var migrate = false
        do {
            if let data = try secure.load() {
                // Only this app can write the item, so a record that doesn't decode falls back to the
                // defaults, never to UserDefaults.
                snapshot = (try? JSONDecoder().decode(SecuritySnapshot.self, from: data)) ?? Self.defaultSecurity
            } else {
                snapshot = Self.legacySecurity(defaults)
                migrate = true
            }
            persistsSecurity = true
        } catch {
            settingsLog.error("Security settings unreadable; using defaults for this session")
            snapshot = Self.defaultSecurity
            persistsSecurity = false
        }
        vaultTimeout = VaultTimeout(stored: snapshot.vaultTimeout) ?? .minutes(15)
        timeoutAction = TimeoutAction(rawValue: snapshot.timeoutAction) ?? .lock
        lockOnSystemLock = snapshot.lockOnSystemLock
        lockOnWindowClose = snapshot.lockOnWindowClose
        clearClipboardSeconds = Self.clipboardChoices.contains { $0.seconds == snapshot.clearClipboardSeconds }
            ? snapshot.clearClipboardSeconds : 60
        minimizeOnCopy = Self.boolean(defaults, "minimizeOnCopy", fallback: false)
        autoTouchID = Self.boolean(defaults, "autoTouchID", fallback: true)
        showWebsiteIcons = Self.boolean(defaults, "showWebsiteIcons", fallback: true)
        let background = Self.boolean(defaults, "keepRunningInBackground", fallback: true)
        keepRunningInBackground = background
        // Earlier builds tied the icon to running in the background: menu bar when on, Dock when off.
        iconPlacement = defaults.string(forKey: "iconPlacement").flatMap(AppIconPlacement.init)
            ?? (background ? .menuBar : .dock)
        // Write the Keychain record at once, so UserDefaults is never consulted again, even for
        // someone who never opens the security settings.
        if migrate, saveSecurity() {
            for key in Self.legacySecurityKeys { defaults.removeObject(forKey: key) }
        }
    }

    private static let defaultSecurity = SecuritySnapshot(
        vaultTimeout: VaultTimeout.minutes(15).stored, timeoutAction: TimeoutAction.lock.rawValue,
        lockOnSystemLock: true, lockOnWindowClose: false, clearClipboardSeconds: 60)

    private static func legacySecurity(_ defaults: UserDefaults) -> SecuritySnapshot {
        var snapshot = defaultSecurity
        if let stored = defaults.string(forKey: "vaultTimeout"), VaultTimeout(stored: stored) != nil {
            snapshot.vaultTimeout = stored
        } else if let legacy = defaults.object(forKey: "vaultTimeoutMinutes") as? Int {
            // Earlier builds stored minutes, with 0 meaning "never".
            snapshot.vaultTimeout = (legacy > 0 ? VaultTimeout.minutes(legacy) : .onRestart).stored
        }
        snapshot.timeoutAction = defaults.string(forKey: "timeoutAction") ?? snapshot.timeoutAction
        snapshot.lockOnSystemLock = boolean(defaults, "lockOnSystemLock", fallback: snapshot.lockOnSystemLock)
        snapshot.lockOnWindowClose = boolean(defaults, "lockOnWindowClose", fallback: snapshot.lockOnWindowClose)
        snapshot.clearClipboardSeconds = defaults.object(forKey: "clearClipboardSeconds") as? Int
            ?? snapshot.clearClipboardSeconds
        return snapshot
    }

    @discardableResult
    private func saveSecurity() -> Bool {
        guard persistsSecurity else { return false }
        let snapshot = SecuritySnapshot(
            vaultTimeout: vaultTimeout.stored, timeoutAction: timeoutAction.rawValue,
            lockOnSystemLock: lockOnSystemLock, lockOnWindowClose: lockOnWindowClose,
            clearClipboardSeconds: clearClipboardSeconds)
        do {
            try secure.save(try JSONEncoder().encode(snapshot))
            return true
        } catch {
            settingsLog.error("Could not save security settings to the Keychain")
            return false
        }
    }

    /// Whether a system event should end the session under the current timeout.
    func locksOn(sleep: Bool) -> Bool {
        switch vaultTimeout {
        case .onRestart: false
        case .onSleep: sleep
        case .onSystemLock: true
        case .minutes: lockOnSystemLock
        }
    }

    private static func boolean(_ defaults: UserDefaults, _ key: String, fallback: Bool) -> Bool {
        guard let value = defaults.object(forKey: key) as? NSNumber,
              CFGetTypeID(value) == CFBooleanGetTypeID() else { return fallback }
        return value.boolValue
    }
}

/// The per-account opt-in that lets browsers ask for the Touch ID key. It is a Keychain item that
/// exists only while the opt-in is on; the UserDefaults flag earlier builds kept is discarded, not
/// migrated, so a planted value can never turn browser unlock on.
@MainActor
enum BrowserUnlockPreference {
    static func isEnabled(_ accountHash: String) -> Bool {
        AppSettings.accountDefaults.removeObject(forKey: "firefoxBiometrics.\(accountHash)")
        return ((try? PlatformCredentials.read(PlatformCredentials.browserUnlock, accountHash)) ?? nil) != nil
    }

    static func set(_ enabled: Bool, _ accountHash: String) {
        do {
            if enabled { try PlatformCredentials.store(Data([1]), service: PlatformCredentials.browserUnlock, account: accountHash) }
            else { try PlatformCredentials.delete(PlatformCredentials.browserUnlock, accountHash) }
        } catch {
            settingsLog.error("Could not save the browser unlock preference")
        }
    }
}

extension Duration {
    /// "10 seconds", "1 minute", "4 hours" in the user's language, in the largest whole unit.
    var spelledOut: String {
        formatted(.units(allowed: [.hours, .minutes, .seconds], width: .wide, maximumUnitCount: 1))
    }
}
