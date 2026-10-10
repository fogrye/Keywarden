import Foundation
import XCTest
@testable import Keywarden

/// Clone and passkey-removal drafts; the server round trips are in `VaultIntegrationTests`.
@MainActor
final class ItemCloneTests: XCTestCase {
    private func login() -> ItemData {
        var item = ItemData.new(.login, folderId: "folder")
        item.id = "source-id"
        item.name = "Mail"
        item.favorite = true
        item.login = LoginData(username: "me", password: "secret", totp: "JBSWY3DPEHPK3PXP",
                               uris: [UriData(uri: "https://mail.example", match: 3)])
        item.fields = [FieldData(name: "PIN", value: "1", type: 1)]
        item.removePasskeys = true
        return item
    }

    func testCloneHasNoIdAndASuffixedName() {
        let clone = login().cloned()
        XCTAssertNil(clone.id)
        XCTAssertEqual(clone.name, "Mail - Clone")
        XCTAssertNil(clone.removePasskeys)
        XCTAssertEqual(clone.login?.password, "secret")
        XCTAssertEqual(clone.login?.uris.first?.match, 3)
        XCTAssertEqual(clone.fields.first?.value, "1")
        XCTAssertEqual(clone.folderId, "folder")
    }

    func testCloneCarriesNoPasskeyAttachmentOrHistoryFields() throws {
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(login().cloned())) as? [String: Any]
        let keys = Set(try XCTUnwrap(json).keys)
        for forbidden in ["id", "removePasskeys", "passkeys", "attachments", "passwordHistory", "key",
                          "creationDate", "revisionDate", "fido2Credentials"] {
            XCTAssertFalse(keys.contains(forbidden), forbidden)
        }
    }

    func testClonedEditorIsSavableAsIs() {
        let clone = login().cloned()
        let editor = ItemEditor(draft: clone, original: ItemData(type: clone.type), isClone: true)
        XCTAssertTrue(editor.isNew)
        XCTAssertTrue(editor.isDirty)
        XCTAssertTrue(editor.isValid)
    }

    func testPasskeyRemovalIsOptInAndOnlyEncodedWhenSet() throws {
        var item = ItemData.new(.login, folderId: nil)
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(item)) as? [String: Any]
        XCTAssertNil(json?["removePasskeys"], "edits keep passkeys by default")
        item.removePasskeys = true
        json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(item)) as? [String: Any]
        XCTAssertEqual(json?["removePasskeys"] as? Bool, true)
        // Requesting removal makes the draft dirty, so Save enables.
        let editor = ItemEditor(draft: item, original: ItemData.new(.login, folderId: nil))
        XCTAssertTrue(editor.isDirty)
    }

    func testNewTypesAreCreatable() {
        for type in [VaultItemType.bankAccount, .driversLicense, .passport] {
            XCTAssertTrue(VaultItemType.creatable.contains(type))
            let item = ItemData.new(type, folderId: nil)
            XCTAssertNotNil(item.bankAccount ?? item.driversLicense.map { _ in BankAccountData() } ?? item.passport.map { _ in BankAccountData() })
        }
        XCTAssertFalse(VaultItemType.creatable.contains(.sshKey))
    }
}
