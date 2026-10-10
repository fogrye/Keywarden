import AppKit
import SwiftUI
import XCTest
@testable import Keywarden

/// The Export Vault and Import Data sheets driven through their accessibility tree, with stub file
/// panels, against the disposable server (`BW_TEST_*`).
@MainActor
final class TransferFlowTests: XCTestCase {
    private var scratch: URL!

    override func setUp() async throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("transfer-flow-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override class func tearDown() {
        SeededSession.end()
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    private func waitFor(_ hosted: HostedWindow, identifier: String, timeout: TimeInterval = 20) async throws -> AXTree {
        let deadline = Date().addingTimeInterval(timeout)
        var tree = try await hosted.tree(settle: 0.3)
        while tree.node(identifier: identifier) == nil, Date() < deadline {
            try await Task.sleep(for: .milliseconds(300))
            tree = AXTree(hosted.host)
        }
        return tree
    }

    /// Format choices and warnings, the master-password gate, a wrong password writing nothing,
    /// and a right one writing the file and reporting counts.
    func testExportSheetGatesOnTheMasterPasswordAndWritesTheFile() async throws {
        let account = try VaultFlowTests.account()
        let model = try await VaultFlowTests.signedIn(account)
        let panels = StubPanels()
        let destination = scratch.appendingPathComponent("export.json")
        panels.exportDestination = destination
        let hosted = HostedWindow(ExportSheet(model: model, panels: panels)
            .background(Color(nsColor: .windowBackgroundColor)), size: NSSize(width: 520, height: 520))
        defer { hosted.close() }

        var tree = try await waitFor(hosted, identifier: "exportConfirm")
        XCTAssertTrue(tree.contains("Export Vault"))
        XCTAssertNotNil(tree.node(identifier: "exportFormat"))
        XCTAssertNotNil(tree.node(identifier: "exportWarning"), "unencrypted formats carry a warning")
        XCTAssertEqual(tree.node(identifier: "exportConfirm")?.enabled, false, "the master password comes first")

        // A wrong master password stops before the panel opens; nothing is written.
        try await hosted.type("not-the-password", identifier: "exportMasterPassword")
        tree = AXTree(hosted.host)
        XCTAssertEqual(tree.node(identifier: "exportConfirm")?.enabled, true)
        try await hosted.press(identifier: "exportConfirm")
        tree = try await waitFor(hosted, identifier: "exportError")
        XCTAssertNotNil(tree.node(identifier: "exportError"), "a wrong master password is reported")
        XCTAssertTrue(panels.exportRequests.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))

        try await hosted.type(account.password, identifier: "exportMasterPassword")
        try await hosted.press(identifier: "exportConfirm")
        tree = try await waitFor(hosted, identifier: "exportDone")
        XCTAssertNotNil(tree.node(identifier: "exportDone"), "\(tree.texts)")
        XCTAssertTrue(tree.texts.contains { $0.hasPrefix("Exported") })
        XCTAssertEqual(panels.exportRequests.first?.ext, "json")
        XCTAssertTrue(FileManager.default.fileExists(atPath: destination.path))
        let exported = try String(contentsOf: destination, encoding: .utf8)
        XCTAssertTrue(exported.contains("Seed Login"))
    }

    /// Picking the encrypted format asks for how to protect the file; password-protected files
    /// need matching file passwords, and the unencrypted warning goes away.
    func testEncryptedExportAsksForProtectionAndAFilePassword() async throws {
        let model = VaultModel()
        var options = ExportOptions()
        options.format = .encryptedJSON
        options.protection = .password
        var hosted = HostedWindow(ExportSheet(model: model, options: options)
            .background(Color(nsColor: .windowBackgroundColor)), size: NSSize(width: 520, height: 560))
        var tree = try await waitFor(hosted, identifier: "exportConfirm")
        XCTAssertNil(tree.node(identifier: "exportWarning"), "encrypted exports carry no warning")
        XCTAssertNotNil(tree.node(identifier: "exportProtection"))
        XCTAssertTrue(tree.contains("File password"))
        XCTAssertTrue(tree.contains("Confirm file password"))
        try await hosted.type("hunter2", label: "File password")
        try await hosted.type("hunter3", label: "Confirm file password")
        try await hosted.type("master", identifier: "exportMasterPassword")
        tree = AXTree(hosted.host)
        XCTAssertEqual(tree.node(identifier: "exportConfirm")?.enabled, false, "mismatched file passwords")
        try await hosted.type("hunter2", label: "Confirm file password")
        tree = AXTree(hosted.host)
        XCTAssertEqual(tree.node(identifier: "exportConfirm")?.enabled, true)
        hosted.close()

        options.protection = .account
        hosted = HostedWindow(ExportSheet(model: model, options: options)
            .background(Color(nsColor: .windowBackgroundColor)), size: NSSize(width: 520, height: 560))
        defer { hosted.close() }
        tree = try await waitFor(hosted, identifier: "exportConfirm")
        XCTAssertFalse(tree.contains("File password"))
    }

    /// Choose a file, read the counts, confirm, and the items land in the vault.
    func testImportSheetPreviewsConfirmsAndImports() async throws {
        let account = try VaultFlowTests.account()
        let model = try await VaultFlowTests.signedIn(account)
        let tag = String(UUID().uuidString.prefix(8))
        addTeardownBlock { @MainActor in
            for item in model.items where item.name.hasSuffix(tag) {
                await model.moveToTrash(item.id)
                await model.deletePermanently(item.id)
            }
        }
        let file = scratch.appendingPathComponent("bitwarden.json")
        try Data("""
        {"encrypted":false,"folders":[],"items":[
         {"id":"a","type":1,"name":"Sheet Login \(tag)","login":{"username":"sheet.user","password":"sheet-pw"}},
         {"id":"b","type":2,"name":"Sheet Note \(tag)","notes":"words"}]}
        """.utf8).write(to: file)
        let panels = StubPanels()
        panels.importFile = file
        let before = model.items.count
        let hosted = HostedWindow(ImportSheet(model: model, panels: panels)
            .background(Color(nsColor: .windowBackgroundColor)), size: NSSize(width: 520, height: 420))
        defer { hosted.close() }

        var tree = try await waitFor(hosted, identifier: "importChoose")
        XCTAssertTrue(tree.contains("Import Data"))
        try await hosted.press(identifier: "importChoose")
        XCTAssertEqual(panels.importRequests, 1)
        tree = try await waitFor(hosted, identifier: "importCount")
        XCTAssertEqual(tree.node(identifier: "importCount")?.text, "Import 2 items?", "\(tree.texts)")
        XCTAssertTrue(tree.contains("1 Login, 1 Secure Note"))
        XCTAssertEqual(model.items.count, before, "previewing imports nothing")

        try await hosted.press(identifier: "importConfirm")
        tree = try await waitFor(hosted, identifier: "importResult")
        XCTAssertNotNil(tree.node(identifier: "importResult"), "\(tree.texts)")
        XCTAssertNotNil(tree.node(identifier: "importDone"))
        XCTAssertEqual(model.items.filter { $0.name.hasSuffix(tag) }.count, 2)
    }

    /// A cancelled panel leaves the sheet where it was; a password-protected file asks for its
    /// password.
    func testImportSheetCancelledPanelAndPasswordStep() async throws {
        let model = VaultModel()
        let panels = StubPanels()
        var hosted = HostedWindow(ImportSheet(model: model, panels: panels)
            .background(Color(nsColor: .windowBackgroundColor)), size: NSSize(width: 520, height: 420))
        _ = try await waitFor(hosted, identifier: "importChoose")
        try await hosted.press(identifier: "importChoose")
        XCTAssertEqual(panels.importRequests, 1)
        var tree = AXTree(hosted.host)
        XCTAssertNotNil(tree.node(identifier: "importChoose"), "cancelling the panel stays on the first step")
        XCTAssertNil(tree.node(identifier: "importCount"))
        hosted.close()

        hosted = HostedWindow(ImportSheet(model: model, panels: panels, needsPassword: true)
            .background(Color(nsColor: .windowBackgroundColor)), size: NSSize(width: 520, height: 460))
        defer { hosted.close() }
        tree = try await waitFor(hosted, identifier: "importContinue")
        XCTAssertNotNil(tree.node(identifier: "importFilePassword"))
        XCTAssertEqual(tree.node(identifier: "importContinue")?.enabled, false, "a file password is needed first")
        try await hosted.type("secret", identifier: "importFilePassword")
        XCTAssertEqual(AXTree(hosted.host).node(identifier: "importContinue")?.enabled, true)
    }
}
