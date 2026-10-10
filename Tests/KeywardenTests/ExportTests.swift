import Foundation
import XCTest
@testable import Keywarden

/// Stands in for the save and open panels: returns fixed URLs and records what it was asked.
@MainActor
final class StubPanels: TransferPanels {
    var exportDestination: URL?
    var importFile: URL?
    private(set) var exportRequests: [(name: String, ext: String)] = []
    private(set) var importRequests = 0

    func chooseExportDestination(suggestedName: String, fileExtension: String) -> URL? {
        exportRequests.append((suggestedName, fileExtension))
        return exportDestination
    }

    func chooseImportFile() -> URL? {
        importRequests += 1
        return importFile
    }
}

/// Export options, file names and the model flow. The panels can't be driven, so the model takes them
/// as a seam.
@MainActor
final class ExportTests: XCTestCase {
    private var scratch: URL!

    override func setUp() async throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("export-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    func testDefaultFileNameFollowsDesktopsPattern() throws {
        let utc = try XCTUnwrap(TimeZone(identifier: "UTC"))
        let date = Date(timeIntervalSince1970: 1_790_000_000) // 2026-09-21 14:13:20 UTC
        XCTAssertEqual(ExportFileName.suggested(extension: "json", now: date, timeZone: utc), "bitwarden_export_20260921141320.json")
        XCTAssertEqual(ExportFileName.suggested(extension: "csv", now: date, timeZone: utc), "bitwarden_export_20260921141320.csv")
        let tokyo = try XCTUnwrap(TimeZone(identifier: "Asia/Tokyo"))
        XCTAssertEqual(ExportFileName.suggested(extension: "json", now: date, timeZone: tokyo), "bitwarden_export_20260921231320.json", "local time")
        let stamp = ExportFileName.suggested(extension: "json")
        XCTAssertNotNil(stamp.wholeMatch(of: /bitwarden_export_\d{14}\.json/))
    }

    func testOptionsMapToRequestFormatsAndExtensions() {
        var options = ExportOptions()
        XCTAssertEqual(options.requestFormat, "json")
        XCTAssertEqual(options.fileExtension, "json")
        XCTAssertEqual(options.isEncrypted, false)
        options.format = .csv
        XCTAssertEqual(options.requestFormat, "csv")
        XCTAssertEqual(options.fileExtension, "csv")
        XCTAssertEqual(options.isEncrypted, false)
        options.format = .encryptedJSON
        XCTAssertEqual(options.requestFormat, "jsonEncryptedAccount")
        XCTAssertEqual(options.fileExtension, "json")
        XCTAssertEqual(options.isEncrypted, true)
        XCTAssertFalse(options.needsFilePassword)
        options.protection = .password
        XCTAssertEqual(options.requestFormat, "jsonEncryptedPassword")
        XCTAssertTrue(options.needsFilePassword)
    }

    func testValidationAsksForTheMasterPasswordAndAMatchingFilePassword() {
        var options = ExportOptions()
        XCTAssertEqual(options.problem(masterPassword: ""), "Enter your master password.")
        XCTAssertNil(options.problem(masterPassword: "x"))
        options.format = .encryptedJSON
        XCTAssertNil(options.problem(masterPassword: "x"), "account restricted needs no file password")
        options.protection = .password
        XCTAssertEqual(options.problem(masterPassword: "x"), "Enter a file password.")
        options.filePassword = "one"
        options.confirmation = "two"
        XCTAssertEqual(options.problem(masterPassword: "x"), "The file passwords don’t match.")
        options.confirmation = "one"
        XCTAssertNil(options.problem(masterPassword: "x"))
        XCTAssertEqual(options.problem(masterPassword: ""), "Enter your master password.")
    }

    func testSummaryWording() {
        XCTAssertEqual(ExportSummary(items: 1, folders: 0, omitted: 0).text, "1 item")
        XCTAssertEqual(ExportSummary(items: 12, folders: 1, omitted: 0).text, "12 items and 1 folder")
        XCTAssertEqual(ExportSummary(items: 3, folders: 2, omitted: 1).text, "3 items and 2 folders")
    }

    func testLockedVaultCannotExportAndNeverOpensThePanel() async {
        let model = VaultModel()
        let panels = StubPanels()
        panels.exportDestination = scratch.appendingPathComponent("never.json")
        do {
            _ = try await model.exportVault(ExportOptions(), masterPassword: "x", panels: panels)
            XCTFail("expected a locked error")
        } catch {
            XCTAssertEqual((error as? VaultError)?.code, "locked")
        }
        XCTAssertTrue(panels.exportRequests.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: scratch.appendingPathComponent("never.json").path))
    }

    /// Every format through the model against the disposable server, with the panel stubbed.
    func testModelExportsEveryFormatAfterReauthentication() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_TEST_SERVER"], let email = environment["BW_TEST_EMAIL"],
              let password = environment["BW_TEST_PASSWORD"], environment["BW_TEST_DATA_DIR"] != nil else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        let model = VaultModel()
        try await wait { model.isReady }
        // Leave the shared test account signed out for the tests that sign in themselves.
        addTeardownBlock { @MainActor in await model.logout() }
        if model.phase == .locked {
            model.password = password
            await model.unlock()
        } else {
            model.email = email
            model.server = server
            model.password = password
            await model.login()
        }
        XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")
        // What an export of the individual vault should hold.
        let exportable = model.items.filter { !$0.deleted && $0.organizationId == nil }
        let jsonTypes = exportable.filter { (1...5).contains($0.type) }
        let csvTypes = exportable.filter { [1, 2].contains($0.type) }
        XCTAssertGreaterThanOrEqual(jsonTypes.count, 6, "the seeded vault")

        let panels = StubPanels()
        let target = scratch.appendingPathComponent("vault.json")
        panels.exportDestination = target

        // A wrong master password is refused before the panel opens; nothing is written.
        do {
            _ = try await model.exportVault(ExportOptions(), masterPassword: "not the password", panels: panels)
            XCTFail("expected a wrong-password error")
        } catch {
            XCTAssertEqual((error as? VaultError)?.code, "invalidPassword")
            XCTAssertEqual(error.localizedDescription, "That master password is incorrect.")
        }
        XCTAssertTrue(panels.exportRequests.isEmpty, "the save panel comes after re-authentication")
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))

        // Cancelling the panel writes nothing.
        panels.exportDestination = nil
        let cancelled = try await model.exportVault(ExportOptions(), masterPassword: password, panels: panels)
        XCTAssertEqual(cancelled, .cancelled)
        XCTAssertEqual(panels.exportRequests.count, 1)
        XCTAssertTrue(panels.exportRequests[0].name.hasPrefix("bitwarden_export_"))
        XCTAssertEqual(panels.exportRequests[0].ext, "json")
        panels.exportDestination = target

        // Plain JSON: the data, folders and the seeded login's password.
        guard case .saved(let json, let savedTo) = try await model.exportVault(ExportOptions(), masterPassword: password, panels: panels) else {
            return XCTFail("expected a saved export")
        }
        XCTAssertEqual(savedTo, target)
        XCTAssertEqual(json.items, jsonTypes.count)
        XCTAssertEqual(json.omitted, exportable.count - jsonTypes.count)
        let document = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: target)) as? [String: Any])
        XCTAssertEqual(document["encrypted"] as? Bool, false)
        let names = Set((document["items"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String })
        XCTAssertEqual(names, Set(jsonTypes.map(\.name)))
        XCTAssertTrue(String(decoding: try Data(contentsOf: target), as: UTF8.self).contains("Seed-Password-1"))
        XCTAssertEqual(json.folders, (document["folders"] as? [Any])?.count)

        // CSV: logins and notes only.
        var csv = ExportOptions()
        csv.format = .csv
        panels.exportDestination = scratch.appendingPathComponent("vault.csv")
        guard case .saved(let csvSummary, _) = try await model.exportVault(csv, masterPassword: password, panels: panels) else {
            return XCTFail("expected a saved CSV export")
        }
        XCTAssertEqual(csvSummary.items, csvTypes.count)
        XCTAssertEqual(panels.exportRequests.last?.ext, "csv")
        let header = String(decoding: try Data(contentsOf: scratch.appendingPathComponent("vault.csv")), as: UTF8.self).prefix(60)
        XCTAssertTrue(header.hasPrefix("folder,favorite,type,name"), String(header))

        // Encrypted: nothing readable in either variant.
        var account = ExportOptions()
        account.format = .encryptedJSON
        var protected = account
        protected.protection = .password
        protected.filePassword = "file-password"
        protected.confirmation = "file-password"
        for (name, options) in [("account.json", account), ("protected.json", protected)] {
            let url = scratch.appendingPathComponent(name)
            panels.exportDestination = url
            guard case .saved(let summary, _) = try await model.exportVault(options, masterPassword: password, panels: panels) else {
                return XCTFail("expected a saved \(name)")
            }
            XCTAssertEqual(summary.items, jsonTypes.count, name)
            let text = String(decoding: try Data(contentsOf: url), as: UTF8.self)
            XCTAssertFalse(text.contains("Seed Login") || text.contains("Seed-Password-1"), "\(name) is encrypted")
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
            XCTAssertEqual(object["encrypted"] as? Bool, true)
            XCTAssertEqual(object["passwordProtected"] as? Bool, name == "protected.json" ? true : nil)
        }
        // No temporary files were left next to the exports.
        let left = try FileManager.default.contentsOfDirectory(atPath: scratch.path).sorted()
        XCTAssertEqual(left, ["account.json", "protected.json", "vault.csv", "vault.json"])
    }

    private func wait(timeout: TimeInterval = 15, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            guard Date() < deadline else { throw XCTSkip("Timed out waiting for condition") }
            try await Task.sleep(for: .milliseconds(50))
        }
    }
}
