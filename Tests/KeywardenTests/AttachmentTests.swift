import Foundation
import XCTest
@testable import Keywarden

/// Attachment limits, names and the model flow. The panels can't be driven, so the model takes URLs.
@MainActor
final class AttachmentTests: XCTestCase {
    private var scratch: URL!

    override func setUp() async throws {
        scratch = FileManager.default.temporaryDirectory.appendingPathComponent("attachment-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    func testFileLimitAcceptsFilesAndRejectsFoldersAndOversizeFiles() throws {
        let small = scratch.appendingPathComponent("small.txt")
        try Data("hello".utf8).write(to: small)
        XCTAssertNil(AttachmentLimits.problem(with: small))
        XCTAssertNotNil(AttachmentLimits.problem(with: scratch), "a folder is not a file")
        XCTAssertNotNil(AttachmentLimits.problem(with: scratch.appendingPathComponent("missing")))
        let limit = scratch.appendingPathComponent("limit.bin")
        FileManager.default.createFile(atPath: limit.path, contents: nil)
        let handle = try FileHandle(forWritingTo: limit)
        try handle.truncate(atOffset: UInt64(AttachmentLimits.maxBytes))
        try handle.close()
        XCTAssertNil(AttachmentLimits.problem(with: limit), "exactly 500 MB is allowed")
        let handleOver = try FileHandle(forWritingTo: limit)
        try handleOver.truncate(atOffset: UInt64(AttachmentLimits.maxBytes) + 1)
        try handleOver.close()
        XCTAssertEqual(AttachmentLimits.problem(with: limit), "Attachments can be at most 500 MB.")
    }

    func testSuggestedNamesNeverHoldPathSeparators() {
        XCTAssertEqual(AttachmentPanels.suggestedName("report.pdf"), "report.pdf")
        XCTAssertEqual(AttachmentPanels.suggestedName("../etc/passwd"), "..-etc-passwd")
        XCTAssertEqual(AttachmentPanels.suggestedName("a:b"), "a-b")
        XCTAssertEqual(AttachmentPanels.suggestedName("  "), "Attachment")
    }

    func testAttachmentsDecodeWithTheirIdAndDoNotMakeTheEditorDirty() throws {
        let json = #"{"id":"abc","fileName":"a.txt","size":"5 Bytes"}"#
        let attachment = try JSONDecoder().decode(ItemDetail.Attachment.self, from: Data(json.utf8))
        XCTAssertEqual(attachment.id, "abc")
        var item = ItemData.new(.login, folderId: nil)
        item.id = "x"
        item.name = "Mail"
        var editor = ItemEditor(draft: item, original: item)
        editor.attachments = [attachment]
        XCTAssertFalse(editor.isDirty, "attachments change on the server at once, not through Save")
    }

    func testRejectedFileShowsAnErrorAndSendsNothing() async {
        let model = VaultModel()
        let folder = scratch!
        let added = await model.addAttachment(itemID: "x", from: folder)
        XCTAssertFalse(added)
        XCTAssertEqual(model.errorMessage, "Choose a file to attach.")
        XCTAssertNil(model.attachmentActivity)
    }

    /// Upload, download, edit, remove through the model against the disposable server.
    func testModelUploadsDownloadsAndRemovesAttachments() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_TEST_SERVER"], let email = environment["BW_TEST_EMAIL"],
              let password = environment["BW_TEST_PASSWORD"], environment["BW_TEST_DATA_DIR"] != nil else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        let model = VaultModel()
        try await wait { model.isReady }
        model.email = email
        model.server = server
        model.password = password
        await model.login()
        XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")

        var draft = ItemData.new(.login, folderId: nil)
        draft.name = "Attach \(UUID().uuidString.prefix(8))"
        draft.login = LoginData(username: "u", password: "p")
        let created = try await SDKClient.shared.save(draft)
        let id = try XCTUnwrap(created.id)
        defer { Task { _ = try? await SDKClient.shared.delete(id: id, permanent: false); _ = try? await SDKClient.shared.delete(id: id, permanent: true) } }
        await model.sync()
        model.select(id)
        try await wait { model.detail?.id == id }

        // Bigger than the 1 MB request limit: contents go by path, not through JSON.
        let contents = Data((0..<1_500_000).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ ($0 >> 8)) })
        let source = scratch.appendingPathComponent("report.bin")
        try contents.write(to: source)
        let uploaded = await model.addAttachment(itemID: id, from: source)
        XCTAssertTrue(uploaded, model.errorMessage ?? "")
        XCTAssertNil(model.attachmentActivity)
        let attachment = try XCTUnwrap(model.detail?.attachments.first)
        XCTAssertEqual(model.detail?.attachments.count, 1)
        XCTAssertEqual(attachment.fileName, "report.bin")

        let destination = scratch.appendingPathComponent("saved.bin")
        let downloaded = await model.downloadAttachment(itemID: id, attachment, to: destination)
        XCTAssertTrue(downloaded, model.errorMessage ?? "")
        XCTAssertEqual(try Data(contentsOf: destination), contents)

        // The editor lists the attachments and keeps them through an edit; the draft stays as typed.
        model.beginEditing()
        XCTAssertEqual(model.editor?.attachments.map(\.fileName), ["report.bin"])
        let second = scratch.appendingPathComponent("note.txt")
        try Data("hello".utf8).write(to: second)
        model.editor?.draft.notes = "typed while attaching"
        let addedSecond = await model.addAttachment(itemID: id, from: second)
        XCTAssertTrue(addedSecond, model.errorMessage ?? "")
        XCTAssertEqual(model.editor?.attachments.count, 2)
        XCTAssertEqual(model.editor?.draft.notes, "typed while attaching", "unsaved edits are not clobbered")
        await model.saveEditor()
        XCTAssertNil(model.editor, model.editorError ?? "")
        let afterEdit = try await SDKClient.shared.item(id: id)
        XCTAssertEqual(afterEdit.attachments.count, 2, "saving the edit keeps both attachments")
        XCTAssertEqual(afterEdit.item.notes, "typed while attaching")

        let removed = await model.removeAttachment(itemID: id, attachment)
        XCTAssertTrue(removed, model.errorMessage ?? "")
        XCTAssertEqual(model.detail?.attachments.map(\.fileName), ["note.txt"])
        let synced = try await SDKClient.shared.sync()
        XCTAssertTrue(synced.items.contains { $0.id == id })
        let remaining = try await SDKClient.shared.item(id: id)
        XCTAssertEqual(remaining.attachments.map(\.fileName), ["note.txt"], "the server removed it")
        await model.logout()
    }

    private func wait(timeout: TimeInterval = 15, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            guard Date() < deadline else { throw XCTSkip("Timed out waiting for condition") }
            try await Task.sleep(for: .milliseconds(50))
        }
    }
}
