import Foundation
import XCTest
@testable import Keywarden

/// Runs inside the app against a disposable account seeded by `cargo test seed_demo_vault`.
/// Supply `BW_TEST_SERVER`, `BW_TEST_EMAIL`, `BW_TEST_PASSWORD`, `BW_TEST_DATA_DIR` and
/// `BW_TEST_NAMESPACE` through the runner environment (`TEST_RUNNER_…`).
@MainActor
final class VaultIntegrationTests: XCTestCase {
    func testSaveEditTrashRestoreDeleteAndOfflineUnlock() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_TEST_SERVER"],
              let email = environment["BW_TEST_EMAIL"],
              let password = environment["BW_TEST_PASSWORD"],
              let isolatedRoot = environment["BW_TEST_DATA_DIR"],
              let namespace = environment["BW_TEST_NAMESPACE"],
              !isolatedRoot.isEmpty, !namespace.isEmpty else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        let client = SDKClient.shared
        let initial = try await client.login(email: email, password: password, server: server)
        let seed = try XCTUnwrap(initial.items.first { $0.name == "Seed Login" })
        let seeded = try await client.item(id: seed.id)
        XCTAssertEqual(seeded.item.login?.password, "Seed-Password-1")
        XCTAssertFalse(seeded.item.fields.isEmpty)
        let code = try await client.totp(id: seed.id)
        XCTAssertEqual(code.code.count, 6)

        // Create, then edit through a decoded detail exactly as the editor does.
        var draft = ItemData.new(.login, folderId: nil)
        draft.name = "Hosted \(UUID().uuidString.prefix(8))"
        draft.login = LoginData(username: "hosted", password: "first", uris: [UriData(uri: "https://example.net")])
        let created = try await client.save(draft)
        let id = try XCTUnwrap(created.id)
        var detail = try await client.item(id: id)
        XCTAssertEqual(detail.item.login?.uris.first?.uri, "https://example.net")
        var edited = detail.item
        edited.login?.password = "second"
        edited.notes = "Notes β\nsecond line"
        _ = try await client.save(edited)
        detail = try await client.item(id: id)
        XCTAssertEqual(detail.item.login?.password, "second")
        XCTAssertEqual(detail.item.notes, "Notes β\nsecond line")
        XCTAssertEqual(detail.passwordHistory.first?.password, "first")

        // Bank accounts, driver's licenses and passports can be created and edited too.
        var bank = ItemData.new(.bankAccount, folderId: nil)
        bank.name = "Bank \(UUID().uuidString.prefix(8))"
        bank.bankAccount?.bankName = "Test Bank"
        bank.bankAccount?.accountNumber = "12345678"
        var license = ItemData.new(.driversLicense, folderId: nil)
        license.name = "Licence \(UUID().uuidString.prefix(8))"
        license.driversLicense?.firstName = "Alex"
        license.driversLicense?.licenseNumber = "D123"
        var passport = ItemData.new(.passport, folderId: nil)
        passport.name = "Passport \(UUID().uuidString.prefix(8))"
        passport.passport?.surname = "Example"
        passport.passport?.passportNumber = "P123"
        for draft in [bank, license, passport] {
            let result: MutationResult
            do {
                result = try await client.save(draft)
            } catch let error as VaultError where error.code == "saveFailed" {
                // Older Bitwarden-compatible servers predate these item types and reject them.
                print("server rejected \(draft.kind.title); skipping its round trip")
                continue
            }
            let newID = try XCTUnwrap(result.id)
            let saved = try await client.item(id: newID)
            XCTAssertEqual(saved.item.kind, draft.kind)
            XCTAssertEqual(saved.item.bankAccount?.accountNumber, draft.bankAccount?.accountNumber)
            XCTAssertEqual(saved.item.driversLicense?.licenseNumber, draft.driversLicense?.licenseNumber)
            XCTAssertEqual(saved.item.passport?.passportNumber, draft.passport?.passportNumber)
            var edit = saved.item
            edit.notes = "edited"
            _ = try await client.save(edit)
            _ = try await client.delete(id: newID, permanent: false)
            _ = try await client.delete(id: newID, permanent: true)
        }

        // Clone: the copy has its own id and the source is unchanged.
        let source = try await client.item(id: id)
        let cloneResult = try await client.save(source.item.cloned())
        let cloneID = try XCTUnwrap(cloneResult.id)
        XCTAssertNotEqual(cloneID, id)
        let copy = try await client.item(id: cloneID)
        XCTAssertEqual(copy.item.name, source.item.name + " - Clone")
        XCTAssertEqual(copy.item.login?.password, source.item.login?.password)
        XCTAssertTrue(copy.passwordHistory.isEmpty)
        XCTAssertTrue(copy.attachments.isEmpty)
        let unchanged = try await client.item(id: id)
        XCTAssertEqual(unchanged.item.name, source.item.name)
        XCTAssertEqual(unchanged.passwordHistory.count, source.passwordHistory.count)
        _ = try await client.delete(id: cloneID, permanent: false)
        _ = try await client.delete(id: cloneID, permanent: true)

        let trashed = try await client.delete(id: id, permanent: false)
        XCTAssertEqual(trashed.snapshot.items.first { $0.id == id }?.deleted, true)
        let restored = try await client.restore(id: id)
        XCTAssertEqual(restored.snapshot.items.first { $0.id == id }?.deleted, false)

        // The saved change is in the local cache after a lock, without a network round trip.
        client.invalidateSession()
        try await client.lock()
        let locked = try await client.status()
        XCTAssertEqual(locked.phase, .locked)
        let unlocked = try await client.unlock(password: password)
        XCTAssertTrue(unlocked.items.contains { $0.id == id })
        let cached = try await client.item(id: id)
        XCTAssertEqual(cached.item.login?.password, "second")

        _ = try await client.delete(id: id, permanent: false)
        let gone = try await client.delete(id: id, permanent: true)
        XCTAssertFalse(gone.snapshot.items.contains { $0.id == id })
        client.invalidateSession()
        try await client.logout()
        let loggedOut = try await client.status()
        XCTAssertEqual(loggedOut.phase, .loggedOut)
    }
}
