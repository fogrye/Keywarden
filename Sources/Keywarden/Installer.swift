import AppKit
import Foundation
import os

let installLog = Logger(subsystem: "xyz.kuvshynov.Keywarden", category: "core")

private enum InstallError: Error, CustomStringConvertible, LocalizedError {
    case invalid(String)
    var description: String {
        switch self { case .invalid(let reason): reason }
    }
    var errorDescription: String? { description }
}

/// Registers this app's signed helper as a browser's `com.8bit.bitwarden` native-messaging host.
///
/// An app running from /Applications or ~/Applications is registered where it is. Anywhere else
/// (for example a build folder) it is first copied to Application Support, because browsers need
/// a path that survives rebuilds. A host owned by another app is backed up on each takeover (the
/// latest one wins) and restored on disconnect. A browser stays connected until it is disconnected
/// here: when another app (such as Bitwarden Desktop on launch) replaces or removes its host,
/// `reclaim` takes it back.
enum Installer {
    enum Registration: Equatable, Sendable {
        case none
        /// Registered to one of this app's helpers, at `app`.
        case this(app: URL)
        case other(path: String)
    }

    struct BrowserStatus: Identifiable, Equatable, Sendable {
        let browser: KnownBrowser
        /// The installed browser app, if found.
        let app: URL?
        let registration: Registration
        let hasBackup: Bool
        /// Connecting is possible: a built-in requirement exists or the app's signature can be pinned.
        let verifiable: Bool
        var id: String { browser.id }
    }

    private static let helperPath = "Contents/Helpers/keywarden-native-host"
    private static var files: FileManager { FileManager.default }
    private static var home: URL { files.homeDirectoryForCurrentUser }
    private static var base: URL { home.appendingPathComponent("Library/Application Support/Keywarden") }
    private static var copy: URL { base.appendingPathComponent("Keywarden.app") }
    private static var running: URL { Bundle.main.bundleURL.standardizedFileURL }

    /// Serializes connection changes, so a reclaim never races the user connecting or disconnecting.
    private static let changes = NSRecursiveLock()

    private static func backup(_ browser: KnownBrowser) -> URL {
        base.appendingPathComponent("original-host-\(browser.id).json")
    }

    private static var runsFromApplications: Bool {
        let parent = running.deletingLastPathComponent().path
        return parent == "/Applications" || parent == home.appendingPathComponent("Applications").path
    }

    /// Whether this is the copy in Applications, which browsers launch directly.
    static var isInstalled: Bool { runsFromApplications }

    /// The bundle that connecting registers.
    static var target: URL { runsFromApplications ? running : copy }

    private static func helper(in app: URL) -> URL { app.appendingPathComponent(helperPath) }

    private static func manifestOwner(_ browser: KnownBrowser) -> String? {
        guard let data = try? Data(contentsOf: browser.manifestURL(home: home)) else { return nil }
        let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        return object?["path"] as? String ?? ""
    }

    /// The app bundle whose signed helper a manifest path names, if it is one of ours.
    private static func ownedApp(_ path: String) -> URL? {
        guard path.hasSuffix("/" + helperPath) else { return nil }
        let app = URL(fileURLWithPath: String(path.dropLast(helperPath.count + 1))).standardizedFileURL
        guard (try? PeerIdentity.verifySignedHelper(at: helper(in: app), team: PeerIdentity.currentTeam())) != nil
        else { return nil }
        return app
    }

    private static func installedApp(_ browser: KnownBrowser) -> URL? {
        browser.bundleIDs.lazy.compactMap { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }.first
    }

    // MARK: Status

    /// Browsers that are installed, plus uninstalled ones still registered to this app.
    static func browsers() -> [BrowserStatus] {
        BrowserRegistry.all.compactMap { browser in
            let app = installedApp(browser)
            let registration: Registration = switch manifestOwner(browser) {
            case .none: .none
            case .some(let path): ownedApp(path).map { .this(app: $0) } ?? .other(path: path)
            }
            // An uninstalled browser is listed only while it still points at this app, so it can be
            // disconnected; other apps' leftover registrations are not ours to show.
            if app == nil {
                guard case .this = registration else { return nil }
            }
            let verifiable = !browser.builtInRequirements.isEmpty || app.map(pinnable) == true
            return BrowserStatus(browser: browser, app: app, registration: registration,
                                 hasBackup: files.fileExists(atPath: backup(browser).path), verifiable: verifiable)
        }
    }

    /// One pass over the browsers, with the warnings derived from it. It checks code signatures,
    /// which can take seconds for a large browser, so call it off the main thread.
    struct Scan: Equatable, Sendable {
        var browsers: [BrowserStatus]
        /// A registered Application Support copy differs from the running app.
        var outdated: Bool
        /// Some browser launches a different copy of this app than the one connecting would register.
        var elsewhere: Bool
    }

    static func scan() -> Scan {
        let statuses = browsers()
        let registered = statuses.compactMap { status -> URL? in
            guard case .this(let app) = status.registration else { return nil }
            return app
        }
        return Scan(browsers: statuses,
                    outdated: registered.contains { $0 == copy.standardizedFileURL && $0 != running && !sameBuild($0, running) },
                    elsewhere: registered.contains { $0 != target.standardizedFileURL })
    }

    /// `PeerIdentity.browserPin` validates the whole browser bundle. The status list only needs to
    /// know whether a pin exists, so it reuses the answer until the browser is updated (its
    /// Info.plist changes). Connecting always checks the signature afresh.
    private static let pinCache = OSAllocatedUnfairLock(initialState: [String: (Date?, Bool)]())

    private static func pinnable(_ app: URL) -> Bool {
        let stamp = (try? app.appendingPathComponent("Contents/Info.plist")
            .resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
        if let cached = pinCache.withLock({ $0[app.path] }), cached.0 == stamp { return cached.1 }
        let result = PeerIdentity.browserPin(at: app) != nil
        pinCache.withLock { $0[app.path] = (stamp, result) }
        return result
    }

    private static func sameBuild(_ first: URL, _ second: URL) -> Bool {
        let path = "Contents/MacOS/keywarden"
        let keys: Set<URLResourceKey> = [.fileSizeKey, .contentModificationDateKey]
        guard let a = try? first.appendingPathComponent(path).resourceValues(forKeys: keys),
              let b = try? second.appendingPathComponent(path).resourceValues(forKeys: keys) else { return false }
        return a.fileSize == b.fileSize && a.contentModificationDate == b.contentModificationDate
    }

    // MARK: Connect and disconnect

    /// Registers this app with `browser`. `replace` allows taking over another app's host.
    static func connect(_ browser: KnownBrowser, replace: Bool) throws {
        changes.lock(); defer { changes.unlock() }
        let pin: String?
        if browser.builtInRequirements.isEmpty {
            guard let app = installedApp(browser) else {
                throw InstallError.invalid(String(localized: "\(browser.name) isn’t installed."))
            }
            guard let requirement = PeerIdentity.browserPin(at: app) else {
                throw InstallError.invalid(String(localized: "\(browser.name)’s signature can’t be verified, so it can’t be connected safely."))
            }
            pin = requirement
        } else {
            pin = nil
        }
        let destination = try prepareApp()
        let manifest = browser.manifestURL(home: home)
        if files.fileExists(atPath: manifest.path) {
            let existing = try Data(contentsOf: manifest)
            let owner = (try? JSONSerialization.jsonObject(with: existing) as? [String: Any])?["path"] as? String
            if owner.flatMap(ownedApp) == nil {
                guard replace else {
                    throw InstallError.invalid(String(localized: "\(browser.name) already has a Bitwarden connection. Replace it to take over."))
                }
                // A backup left from an earlier takeover means the other app re-registered since
                // (for example Bitwarden Desktop on launch). Its current host is the one to restore.
                try existing.write(to: backup(browser), options: .atomic)
            }
        }
        try files.createDirectory(at: manifest.deletingLastPathComponent(), withIntermediateDirectories: true)
        var object: [String: Any] = ["name": BrowserRegistry.hostName,
                                     "description": "Keywarden",
                                     "path": helper(in: destination).path, "type": "stdio"]
        switch browser.family {
        case .firefox: object["allowed_extensions"] = [BrowserRegistry.firefoxExtensionID]
        case .chromium: object["allowed_origins"] = BrowserRegistry.chromiumOrigins
        }
        let contents = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        try contents.write(to: manifest, options: .atomic)
        var pins = BrowserPins.load(home: home)
        pins[browser.id] = pin
        try BrowserPins.save(pins, home: home)
        var ids = kept()
        if ids.insert(browser.id).inserted { try saveKept(ids) }
        FileHandle.standardError.write(Data("Connected \(browser.name) at \(manifest.path)\n".utf8))
    }

    /// Unregisters this app from `browser`, restoring the host it replaced, if any.
    static func disconnect(_ browser: KnownBrowser) throws {
        changes.lock(); defer { changes.unlock() }
        guard let owner = manifestOwner(browser), ownedApp(owner) != nil else {
            throw InstallError.invalid(String(localized: "\(browser.name) isn’t connected to this app; nothing changed."))
        }
        // Before the other app's host is restored, so it isn't reclaimed.
        var ids = kept()
        if ids.remove(browser.id) != nil { try saveKept(ids) }
        let manifest = browser.manifestURL(home: home)
        if files.fileExists(atPath: backup(browser).path) {
            try Data(contentsOf: backup(browser)).write(to: manifest, options: .atomic)
            try files.removeItem(at: backup(browser))
        } else {
            try files.removeItem(at: manifest)
        }
        var pins = BrowserPins.load(home: home)
        pins[browser.id] = nil
        try BrowserPins.save(pins, home: home)
        FileHandle.standardError.write(Data("Disconnected \(browser.name). Enrolled keys remain in Keychain.\n".utf8))
    }

    /// Re-registers every connected browser with this build (after rebuilding or moving the app).
    static func updateConnections() throws {
        for status in browsers() {
            if case .this = status.registration { try connect(status.browser, replace: false) }
        }
    }

    // MARK: Keeping connections

    /// Browsers connected here and not since disconnected.
    private static var keptURL: URL { base.appendingPathComponent("connected.json") }

    static func kept() -> Set<String> {
        if let data = try? Data(contentsOf: keptURL), let ids = try? JSONDecoder().decode([String].self, from: data) {
            return Set(ids)
        }
        let ids = seedKept(browsers(), pinned: Set(BrowserPins.load(home: home).keys))
        try? saveKept(ids)
        return ids
    }

    /// Earlier builds kept no list. A browser counts as connected if it is registered to this app,
    /// or if another app has taken it over since: a backup or a pin is left only by connecting and
    /// removed by disconnecting.
    static func seedKept(_ statuses: [BrowserStatus], pinned: Set<String>) -> Set<String> {
        Set(statuses.compactMap { status -> String? in
            if case .this = status.registration { return status.browser.id }
            return status.hasBackup || pinned.contains(status.browser.id) ? status.browser.id : nil
        })
    }

    private static func saveKept(_ ids: Set<String>) throws {
        try files.createDirectory(at: base, withIntermediateDirectories: true)
        try JSONEncoder().encode(ids.sorted()).write(to: keptURL, options: .atomic)
    }

    /// Folders holding the manifests of every known browser, whether or not they exist yet.
    static var manifestFolders: [URL] {
        Array(Set(BrowserRegistry.all.map { $0.manifestURL(home: home).deletingLastPathComponent().standardizedFileURL }))
    }

    /// Whether a kept browser's host has been replaced or removed by another app. A browser that is
    /// no longer installed is left alone.
    static func needsReclaim(_ registration: Registration, kept: Bool, installed: Bool) -> Bool {
        guard kept, installed else { return false }
        if case .this = registration { return false }
        return true
    }

    /// Takes back the host of every kept browser another app has replaced or removed, except those
    /// in `skipping`. Returns the ids of the browsers taken back. Checks signatures, so call it off
    /// the main thread.
    static func reclaim(skipping: Set<String> = []) -> [String] {
        changes.lock(); defer { changes.unlock() }
        let kept = kept().subtracting(skipping)
        guard !kept.isEmpty else { return [] }
        return browsers().compactMap { status in
            guard needsReclaim(status.registration, kept: kept.contains(status.browser.id), installed: status.app != nil)
            else { return nil }
            do {
                try connect(status.browser, replace: true)
                installLog.notice("Reconnected \(status.browser.name, privacy: .public) after another app replaced its host")
                return status.browser.id
            } catch {
                installLog.error("Couldn’t reconnect \(status.browser.name, privacy: .public): \(error.localizedDescription, privacy: .public)")
                return nil
            }
        }
    }

    /// Verifies this app and puts it where browsers will launch it.
    private static func prepareApp() throws -> URL {
        let source = running
        guard source.pathExtension == "app",
              Bundle.main.bundleIdentifier == PeerIdentity.appID,
              files.fileExists(atPath: source.appendingPathComponent("Contents/embedded.provisionprofile").path) else {
            throw InstallError.invalid(String(localized: "Run this from the provisioned Keywarden.app."))
        }
        let team = try PeerIdentity.currentTeam()
        try PeerIdentity.verifySignedApp(at: source, team: team)
        try PeerIdentity.verifySignedHelper(at: helper(in: source), team: team)
        let destination = target.standardizedFileURL
        try files.createDirectory(at: base, withIntermediateDirectories: true)
        if destination != source {
            if NSWorkspace.shared.runningApplications.contains(where: {
                $0.bundleURL?.standardizedFileURL == destination
            }) {
                throw InstallError.invalid(String(localized: "Quit the installed Keywarden app before replacing its bundle."))
            }
            if !(files.fileExists(atPath: destination.path) && sameBuild(destination, source)) {
                let temporary = base.appendingPathComponent("Keywarden.new.app")
                if files.fileExists(atPath: temporary.path) { try files.removeItem(at: temporary) }
                try files.copyItem(at: source, to: temporary)
                if files.fileExists(atPath: destination.path) { try files.removeItem(at: destination) }
                try files.moveItem(at: temporary, to: destination)
            }
        }
        try PeerIdentity.verifySignedHelper(at: helper(in: destination), team: team)
        return destination
    }

    /// Earlier builds kept Firefox's backup as original-host.json.
    static func migrate() {
        let legacy = base.appendingPathComponent("original-host.json")
        guard let firefox = BrowserRegistry.browser("firefox"),
              files.fileExists(atPath: legacy.path),
              !files.fileExists(atPath: backup(firefox).path) else { return }
        try? files.moveItem(at: legacy, to: backup(firefox))
    }

    // MARK: Command line (Firefox, as in earlier builds)

    static func install(replace: Bool) throws {
        guard let firefox = BrowserRegistry.browser("firefox") else { return }
        migrate()
        try connect(firefox, replace: replace)
    }

    static func uninstall() throws {
        guard let firefox = BrowserRegistry.browser("firefox") else { return }
        migrate()
        try disconnect(firefox)
    }
}
