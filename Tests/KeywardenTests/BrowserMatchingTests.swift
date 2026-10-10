import Foundation
import Security
import XCTest
@testable import Keywarden

/// Which browser may launch the helper, decided from its arguments and recorded pins.
final class BrowserMatchingTests: XCTestCase {
    private let home = URL(fileURLWithPath: "/Users/tester")
    private let helper = "/Applications/Keywarden.app/Contents/Helpers/keywarden-native-host"

    private func ids(_ arguments: [String], pins: [String: String] = [:]) -> [String] {
        BrowserRegistry.candidates(arguments: arguments, home: home, pins: pins).map(\.browser.id)
    }

    func testFirefoxFamilyIsMatchedByManifestPathIgnoringCase() {
        let firefox = "/Users/tester/Library/Application Support/Mozilla/NativeMessagingHosts/com.8bit.bitwarden.json"
        // Zen launches through Mozilla's shared registration (seen on a real install).
        XCTAssertEqual(ids([helper, firefox, BrowserRegistry.firefoxExtensionID]), ["firefox", "zen"])
        // The folder on disk is "zen"; Bitwarden writes "Zen"; the filesystem treats them alike.
        let zen = "/Users/tester/Library/Application Support/Zen/NativeMessagingHosts/com.8bit.bitwarden.json"
        XCTAssertEqual(ids([helper, zen, BrowserRegistry.firefoxExtensionID]), ["zen"])
    }

    func testFirefoxFormRejectsOtherExtensionsAndManifests() {
        let firefox = "/Users/tester/Library/Application Support/Mozilla/NativeMessagingHosts/com.8bit.bitwarden.json"
        XCTAssertEqual(ids([helper, firefox, "{another-extension}"]), [])
        XCTAssertEqual(ids([helper, "/tmp/com.8bit.bitwarden.json", BrowserRegistry.firefoxExtensionID]), [])
        XCTAssertEqual(ids([helper]), [])
        XCTAssertEqual(ids([helper, firefox]), [])
    }

    func testChromiumFamilyNeedsARecordedPin() {
        let origin = "chrome-extension://nngceckbapebfimnlniiiahkandclblb/"
        XCTAssertEqual(ids([helper, origin]), [], "No built-in trust for untested Chromium browsers")
        let pin = BrowserRegistry.teamRequirement("EQHXZ8M8AV")
        XCTAssertEqual(ids([helper, origin], pins: ["chrome": pin]), ["chrome"])
        XCTAssertEqual(ids([helper, "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"], pins: ["chrome": pin]), [])
        let candidates = BrowserRegistry.candidates(arguments: [helper, origin], home: home, pins: ["chrome": pin])
        XCTAssertEqual(candidates.first?.requirements, [pin])
    }

    func testEveryBuiltInRequirementCompiles() {
        for browser in BrowserRegistry.all {
            for text in browser.builtInRequirements {
                var requirement: SecRequirement?
                XCTAssertEqual(SecRequirementCreateWithString(text as CFString, [], &requirement), errSecSuccess, text)
            }
        }
    }

    func testInstalledBrowsersSatisfyTheirRequirements() throws {
        for (id, path) in [("firefox", "/Applications/Firefox.app"), ("zen", "/Applications/Zen.app")] {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            let browser = try XCTUnwrap(BrowserRegistry.browser(id))
            var code: SecStaticCode?
            XCTAssertEqual(SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code), errSecSuccess)
            let satisfied = browser.builtInRequirements.contains { text in
                var requirement: SecRequirement?
                guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
                      let requirement, let code else { return false }
                return SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
            }
            XCTAssertTrue(satisfied, "\(path) must satisfy its built-in requirement")
            XCTAssertNotNil(PeerIdentity.browserPin(at: URL(fileURLWithPath: path)), "\(path) must be pinnable")
        }
    }

    func testUnsignedAppsCannotBePinned() throws {
        let app = FileManager.default.temporaryDirectory.appendingPathComponent("Unsigned-\(UUID().uuidString).app")
        try FileManager.default.createDirectory(at: app.appendingPathComponent("Contents/MacOS"),
                                                withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: app) }
        try Data("#!/bin/sh\n".utf8).write(to: app.appendingPathComponent("Contents/MacOS/unsigned"))
        XCTAssertNil(PeerIdentity.browserPin(at: app))
    }

    func testPinsAreIgnoredUnlessPrivate() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("pins-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        let pin = BrowserRegistry.teamRequirement("EQHXZ8M8AV")
        try BrowserPins.save(["chrome": pin, "not-a-browser": "x"], home: home)
        XCTAssertEqual(BrowserPins.load(home: home), ["chrome": pin])
        try FileManager.default.setAttributes([.posixPermissions: 0o644],
                                              ofItemAtPath: BrowserPins.fileURL(home: home).path)
        XCTAssertEqual(BrowserPins.load(home: home), [:], "A world-readable pin file is not trusted")
    }
}
