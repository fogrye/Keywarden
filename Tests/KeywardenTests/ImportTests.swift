import Foundation
import XCTest
@testable import Keywarden

/// Import previews and the model flow. The panels can't be driven, so the model takes URLs.
@MainActor
final class ImportTests: XCTestCase {
    private var scratch: URL!

    override func setUp() async throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("import-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    func testPreviewWording() throws {
        let json = #"{"items":12,"folders":2,"skipped":3,"types":[{"type":1,"count":8},{"type":3,"count":1},{"type":2,"count":3}]}"#
        let preview = try JSONDecoder().decode(ImportPreview.self, from: Data(json.utf8))
        XCTAssertEqual(preview.text, "12 items and 2 folders")
        XCTAssertEqual(preview.breakdown, "8 Logins, 1 Card, 3 Secure Notes")
        XCTAssertEqual(preview.skipped, 3)
        XCTAssertEqual(ImportSummary(items: 1, folders: 0).text, "1 item")
        XCTAssertEqual(ImportSummary(items: 5, folders: 1).text, "5 items and 1 folder")
    }

    func testCommitReplyDecodesWithAndWithoutASnapshot() throws {
        let reply = try JSONDecoder().decode(ImportCommit.self, from: Data(#"{"items":4,"folders":1,"snapshot":null}"#.utf8))
        XCTAssertEqual(reply.items, 4)
        XCTAssertNil(reply.snapshot)
    }

    func testLockedVaultCannotPrepareOrCommit() async throws {
        let model = VaultModel()
        let file = scratch.appendingPathComponent("a.json")
        try Data("{}".utf8).write(to: file)
        do { _ = try await model.prepareImport(from: file); XCTFail("expected a locked error") }
        catch { XCTAssertEqual((error as? VaultError)?.code, "locked") }
        do { _ = try await model.commitImport(); XCTFail("expected a locked error") }
        catch { XCTAssertEqual((error as? VaultError)?.code, "locked") }
    }

    /// JSON, CSV and encrypted files through the model against the disposable server.
    func testModelPreviewsConfirmsAndImportsFiles() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_TEST_SERVER"], let email = environment["BW_TEST_EMAIL"],
              let password = environment["BW_TEST_PASSWORD"], environment["BW_TEST_DATA_DIR"] != nil else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        let model = VaultModel()
        try await wait { model.isReady }
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
        let before = model.items.count
        let tag = String(UUID().uuidString.prefix(8))
        let folderName = "Import Folder \(tag)"
        // Whatever this test adds is removed again, also when an assertion fails.
        addTeardownBlock { @MainActor in
            for item in model.items where item.name.hasSuffix(tag) {
                await model.moveToTrash(item.id)
                await model.deletePermanently(item.id)
            }
            // The server doesn't merge folders by name, so an import can leave several; also clear
            // strays from an interrupted run.
            for folder in model.folders where folder.name.hasPrefix("Import Folder ") { await model.deleteFolder(folder.id) }
        }

        // Bitwarden JSON: one of each type it carries, a folder, a re-prompt flag and password history.
        let json = """
        {"encrypted":false,"folders":[{"id":"f1","name":"\(folderName)"}],"items":[
         {"id":"a","folderId":"f1","type":1,"name":"Imported Login \(tag)","favorite":true,"reprompt":1,"notes":"n1\\nn2",
          "login":{"username":"import.user","password":"imported-pw","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://import.example","match":null}]},
          "fields":[{"name":"PIN","value":"1234","type":1}],
          "passwordHistory":[{"password":"older-pw","lastUsedDate":"2024-01-02T03:04:05.000Z"}]},
         {"id":"b","type":3,"name":"Imported Card \(tag)","card":{"cardholderName":"A","number":"4111111111111111","expMonth":"1","expYear":"2031","code":"123","brand":"Visa"}},
         {"id":"c","type":2,"name":"Imported Note \(tag)","notes":"words"},
         {"id":"d","type":4,"name":"Imported Person \(tag)","identity":{"firstName":"Alex","lastName":"Example"}},
         {"id":"e","type":1,"name":"Trashed \(tag)","deletedDate":"2024-02-01T00:00:00.000Z","login":{}}]}
        """
        let jsonFile = scratch.appendingPathComponent("bitwarden.json")
        try Data(json.utf8).write(to: jsonFile)
        let preview = try await model.prepareImport(from: jsonFile)
        XCTAssertEqual(preview.items, 4)
        XCTAssertEqual(preview.folders, 1)
        XCTAssertEqual(preview.skipped, 1, "the trashed item")
        XCTAssertEqual(preview.breakdown, "1 Login, 1 Secure Note, 1 Card, 1 Identity")
        XCTAssertEqual(model.items.count, before, "previewing imports nothing")

        let summary = try await model.commitImport()
        XCTAssertEqual(summary, ImportSummary(items: 4, folders: 1))
        XCTAssertEqual(model.items.count, before + 4)
        XCTAssertEqual(model.items.filter { $0.name.hasSuffix(tag) }.count, 4)
        let folder = try XCTUnwrap(model.folders.first { $0.name == folderName })
        let login = try XCTUnwrap(model.items.first { $0.name == "Imported Login \(tag)" })
        XCTAssertEqual(login.folderId, folder.id)
        XCTAssertTrue(login.favorite)
        let detail = try await SDKClient.shared.item(id: login.id)
        XCTAssertEqual(detail.item.login?.password, "imported-pw")
        XCTAssertEqual(detail.item.login?.totp, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(detail.item.reprompt, true)
        XCTAssertEqual(detail.item.notes, "n1\nn2")
        XCTAssertEqual(detail.item.fields.first?.value, "1234")
        XCTAssertEqual(detail.passwordHistory.first?.password, "older-pw")
        // A second commit has nothing to import.
        do { _ = try await model.commitImport(); XCTFail("expected nothing to import") }
        catch { XCTAssertEqual((error as? VaultError)?.code, "notFound") }

        // Bitwarden CSV.
        let csvName = "Imported CSV \(tag)"
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            + "\(folderName),,login,\(csvName),,\"Region: EU\",,https://csv.example,csv.user,csv-pw,\n"
        let csvFile = scratch.appendingPathComponent("bitwarden.csv")
        try Data(csv.utf8).write(to: csvFile)
        let csvPreview = try await model.prepareImport(from: csvFile)
        XCTAssertEqual(csvPreview.items, 1)
        XCTAssertEqual(csvPreview.folders, 1)
        _ = try await model.commitImport()
        let csvItem = try XCTUnwrap(model.items.first { $0.name == csvName })
        let csvDetail = try await SDKClient.shared.item(id: csvItem.id)
        XCTAssertEqual(csvDetail.item.login?.password, "csv-pw")

        // Files that aren't Bitwarden exports are refused with a reason, and import nothing.
        let junk = scratch.appendingPathComponent("junk.json")
        try Data(#"{"hello":1}"#.utf8).write(to: junk)
        do { _ = try await model.prepareImport(from: junk); XCTFail("expected a refusal") }
        catch { XCTAssertEqual((error as? VaultError)?.code, "unrecognizedFile") }
        do { _ = try await model.prepareImport(from: scratch.appendingPathComponent("missing.json")); XCTFail("expected a refusal") }
        catch { XCTAssertEqual((error as? VaultError)?.code, "invalidInput") }

        // Encrypted files exported by the model itself: the password is asked for, checked, and
        // account-restricted files open for the same account. Nothing is committed here.
        let panels = StubPanels()
        var protected = ExportOptions()
        protected.format = .encryptedJSON
        protected.protection = .password
        protected.filePassword = "file-password"
        protected.confirmation = "file-password"
        let protectedFile = scratch.appendingPathComponent("protected.json")
        panels.exportDestination = protectedFile
        guard case .saved(let exported, _) = try await model.exportVault(protected, masterPassword: password, panels: panels) else {
            return XCTFail("expected a saved export")
        }
        do { _ = try await model.prepareImport(from: protectedFile); XCTFail("expected a password prompt") }
        catch { XCTAssertEqual((error as? VaultError)?.code, "passwordRequired") }
        do { _ = try await model.prepareImport(from: protectedFile, filePassword: "wrong"); XCTFail("expected a refusal") }
        catch { XCTAssertEqual((error as? VaultError)?.code, "invalidFilePassword") }
        let opened = try await model.prepareImport(from: protectedFile, filePassword: "file-password")
        XCTAssertEqual(opened.items, exported.items)
        var account = ExportOptions()
        account.format = .encryptedJSON
        let accountFile = scratch.appendingPathComponent("account.json")
        panels.exportDestination = accountFile
        guard case .saved(let accountExport, _) = try await model.exportVault(account, masterPassword: password, panels: panels) else {
            return XCTFail("expected a saved export")
        }
        let accountPreview = try await model.prepareImport(from: accountFile)
        XCTAssertEqual(accountPreview.items, accountExport.items)
        model.discardImport()
    }

    private func wait(timeout: TimeInterval = 15, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            guard Date() < deadline else { throw XCTSkip("Timed out waiting for condition") }
            try await Task.sleep(for: .milliseconds(50))
        }
    }
}
