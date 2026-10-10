import Darwin
import Foundation

enum BrowserFamily: String, Codable, Sendable {
    case firefox, chromium
}

/// A browser that can launch the helper through a `com.8bit.bitwarden` native-messaging manifest.
struct KnownBrowser: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let family: BrowserFamily
    let bundleIDs: [String]
    /// Under ~/Library/Application Support; the browser reads NativeMessagingHosts/ inside it.
    let supportPath: String
    /// Requirements for parent processes that need no recorded pin. Only browsers whose signing
    /// was verified on a real install are listed, so their connection survives a missing pin file.
    let builtInRequirements: [String]

    func manifestURL(home: URL) -> URL {
        home.appendingPathComponent("Library/Application Support")
            .appendingPathComponent(supportPath)
            .appendingPathComponent("NativeMessagingHosts/\(BrowserRegistry.hostName).json")
    }
}

enum BrowserRegistry {
    static let hostName = "com.8bit.bitwarden"
    static let firefoxExtensionID = "{446900e4-71c2-419f-a6a7-df9c091e268b}"
    /// Bitwarden's Chrome Web Store, Chrome beta, Edge Add-ons and Opera add-ons extensions.
    static let chromiumOrigins = [
        "chrome-extension://nngceckbapebfimnlniiiahkandclblb/",
        "chrome-extension://hccnnhgbibccigepcmlgppchkpfdophk/",
        "chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh/",
        "chrome-extension://ccnckbpmaceehanjmeomladnmlffdjgn/",
    ]

    /// A Developer ID requirement bound to a signing team: any code that team signed, which covers
    /// a browser's helper processes as well as its main app.
    static func teamRequirement(_ team: String, identifier: String? = nil) -> String {
        let prefix = identifier.map { "identifier \"\($0)\" and " } ?? ""
        return prefix + "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and "
            + "certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"\(team)\""
    }

    static let all: [KnownBrowser] = [
        KnownBrowser(id: "firefox", name: "Firefox", family: .firefox,
                     bundleIDs: ["org.mozilla.firefox", "org.mozilla.firefoxdeveloperedition", "org.mozilla.nightly"],
                     supportPath: "Mozilla",
                     builtInRequirements: ["org.mozilla.firefox", "org.mozilla.firefoxdeveloperedition", "org.mozilla.nightly"]
                        .map { teamRequirement("43AQ936H96", identifier: $0) }),
        KnownBrowser(id: "zen", name: "Zen", family: .firefox, bundleIDs: ["app.zen-browser.zen"],
                     supportPath: "zen",
                     builtInRequirements: [teamRequirement("9V5K9TP787", identifier: "app.zen-browser.zen")]),
        chromium("chrome", "Google Chrome", "com.google.Chrome", "Google/Chrome"),
        chromium("chrome-beta", "Google Chrome Beta", "com.google.Chrome.beta", "Google/Chrome Beta"),
        chromium("chrome-dev", "Google Chrome Dev", "com.google.Chrome.dev", "Google/Chrome Dev"),
        chromium("chrome-canary", "Google Chrome Canary", "com.google.Chrome.canary", "Google/Chrome Canary"),
        chromium("chromium", "Chromium", "org.chromium.Chromium", "Chromium"),
        chromium("edge", "Microsoft Edge", "com.microsoft.edgemac", "Microsoft Edge"),
        chromium("edge-beta", "Microsoft Edge Beta", "com.microsoft.edgemac.Beta", "Microsoft Edge Beta"),
        chromium("edge-dev", "Microsoft Edge Dev", "com.microsoft.edgemac.Dev", "Microsoft Edge Dev"),
        chromium("edge-canary", "Microsoft Edge Canary", "com.microsoft.edgemac.Canary", "Microsoft Edge Canary"),
        chromium("brave", "Brave", "com.brave.Browser", "BraveSoftware/Brave-Browser"),
        chromium("vivaldi", "Vivaldi", "com.vivaldi.Vivaldi", "Vivaldi"),
        chromium("arc", "Arc", "company.thebrowser.Browser", "Arc/User Data"),
        chromium("opera", "Opera", "com.operasoftware.Opera", "com.operasoftware.Opera"),
        chromium("helium", "Helium", "net.imput.helium", "net.imput.helium"),
    ]

    private static func chromium(_ id: String, _ name: String, _ bundleID: String, _ path: String) -> KnownBrowser {
        KnownBrowser(id: id, name: name, family: .chromium, bundleIDs: [bundleID], supportPath: path,
                     builtInRequirements: [])
    }

    static func browser(_ id: String) -> KnownBrowser? { all.first { $0.id == id } }

    /// Paths compare as the filesystem does: case-insensitively and after standardizing, so
    /// `…/zen/…` and `…/Zen/…` are the same manifest.
    static func samePath(_ first: String, _ second: String) -> Bool {
        let a = URL(fileURLWithPath: first).standardizedFileURL.path
        let b = URL(fileURLWithPath: second).standardizedFileURL.path
        return a.compare(b, options: [.caseInsensitive]) == .orderedSame
    }

    /// Which browsers could have launched the helper with these arguments, with the requirements
    /// their parent process must meet. Empty means the launch is refused.
    ///
    /// - Firefox family: `[helper, <manifest path>, <extension id>]`.
    /// - Chromium family: `[helper, chrome-extension://<id>/, …]`.
    static func candidates(arguments: [String], home: URL,
                           pins: [String: String]) -> [(browser: KnownBrowser, requirements: [String])] {
        let browsers: [KnownBrowser]
        if arguments.count == 3, arguments[2] == firefoxExtensionID {
            // Firefox forks such as Zen read Mozilla's shared registration before their own, so a
            // launch through it may come from any Firefox-family browser; each is still held to
            // its own signing requirement.
            let shared = all.first { $0.id == "firefox" }.map { samePath($0.manifestURL(home: home).path, arguments[1]) } ?? false
            browsers = all.filter {
                $0.family == .firefox && (shared || samePath($0.manifestURL(home: home).path, arguments[1]))
            }
        } else if arguments.count >= 2, chromiumOrigins.contains(arguments[1]) {
            browsers = all.filter { $0.family == .chromium }
        } else {
            browsers = []
        }
        return browsers.compactMap { browser in
            let requirements = browser.builtInRequirements + (pins[browser.id].map { [$0] } ?? [])
            return requirements.isEmpty ? nil : (browser, requirements)
        }
    }
}

/// Requirements recorded when a browser is connected, in a user-only file the helper reads.
enum BrowserPins {
    static func fileURL(home: URL) -> URL {
        home.appendingPathComponent("Library/Application Support/Keywarden/browsers.json")
    }

    /// Returns no pins unless the file and its directory are private to this user.
    static func load(home: URL) -> [String: String] {
        let url = fileURL(home: home)
        var directory = stat(), file = stat()
        guard lstat(url.deletingLastPathComponent().path, &directory) == 0,
              directory.st_mode & S_IFMT == S_IFDIR, directory.st_uid == geteuid(),
              directory.st_mode & 0o022 == 0,
              lstat(url.path, &file) == 0, file.st_mode & S_IFMT == S_IFREG,
              file.st_uid == geteuid(), file.st_mode & 0o077 == 0, file.st_nlink == 1,
              file.st_size < 64 * 1024,
              let data = try? Data(contentsOf: url),
              let pins = try? JSONDecoder().decode([String: String].self, from: data) else { return [:] }
        return pins.filter { BrowserRegistry.browser($0.key) != nil }
    }

    static func save(_ pins: [String: String], home: URL) throws {
        let url = fileURL(home: home)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(pins)
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".browsers-\(UUID().uuidString).json")
        guard FileManager.default.createFile(atPath: temporary.path, contents: data,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        if rename(temporary.path, url.path) != 0 {
            try? FileManager.default.removeItem(at: temporary)
            throw CocoaError(.fileWriteUnknown)
        }
    }
}
