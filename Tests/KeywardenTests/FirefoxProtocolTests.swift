import Foundation
import Security
import XCTest
@testable import Keywarden

/// Plays the Firefox extension's side of the legacy native-messaging protocol against the real
/// handler, following apps/browser/src/background/nativeMessaging.background.ts. Credentials use
/// the Debug in-memory store, so no Touch ID prompt appears.
@MainActor
final class FirefoxProtocolTests: XCTestCase {
    private let appID = "firefox-test-\(UUID().uuidString)"
    private let connection: UInt64 = 9_001

    func testHandshakeStatusAndUnlockProduceAKeyThatUnlocksTheVault() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_TEST_SERVER"], let email = environment["BW_TEST_EMAIL"],
              let password = environment["BW_TEST_PASSWORD"], environment["BW_TEST_DATA_DIR"] != nil else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        let client = SDKClient.shared
        let snapshot = try await client.login(email: email, password: password, server: server)
        try await client.enrollBiometrics(generation: client.generation())
        let coordinator = BiometricCoordinator.shared
        coordinator.configure(id: snapshot.accountId, hash: snapshot.accountHash,
                              server: snapshot.server, email: snapshot.email)
        coordinator.setBrowserEnabled(true)
        defer {
            coordinator.setBrowserEnabled(false)
            Legacy.clear(connectionID: connection)
        }

        // A different account gets an explicit wrongUserId instead of silence.
        let (_, otherPublic) = try rsaKeyPair()
        let wrong = try reply(to: ["command": "setupEncryption", "publicKey": otherPublic,
                                   "userId": UUID().uuidString.lowercased(), "messageId": 0,
                                   "timestamp": now()])
        XCTAssertEqual(wrong["command"] as? String, "wrongUserId")

        // Handshake: the app answers with a 64-byte secret wrapped for our RSA key (OAEP-SHA1).
        let (privateKey, publicKey) = try rsaKeyPair()
        let setup = try reply(to: ["command": "setupEncryption", "publicKey": publicKey,
                                   "userId": snapshot.accountId, "messageId": 0, "timestamp": now()])
        XCTAssertEqual(setup["appId"] as? String, appID)
        XCTAssertEqual(setup["command"] as? String, "setupEncryption")
        let wrapped = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(setup["sharedSecret"] as? String)))
        let secret = try XCTUnwrap(SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA1,
                                                             wrapped as CFData, nil) as Data?)
        XCTAssertEqual(secret.count, 64)

        let status = try encryptedCall(["command": "getBiometricsStatusForUser",
                                        "userId": snapshot.accountId, "messageId": 1], secret: secret)
        let code = try XCTUnwrap(status["response"] as? Int)
        XCTAssertTrue([0, 1, 2].contains(code), "Enrolled, opted-in account must not report \(code)")

        let unlock = try encryptedCall(["command": "unlockWithBiometricsForUser",
                                        "userId": snapshot.accountId, "messageId": 2], secret: secret)
        XCTAssertEqual(unlock["response"] as? Bool, true)
        let keyB64 = try XCTUnwrap(unlock["userKeyB64"] as? String)
        XCTAssertNotNil(Data(base64Encoded: keyB64), "userKeyB64 must be base64 key bytes")

        // What Firefox does next: unlock with that key. Here: lock the app and unlock with it.
        client.invalidateSession()
        try await client.lock()
        let unlocked = try await client.unlockBiometrics(authorization: Data(keyB64.utf8),
                                                         generation: client.generation())
        XCTAssertEqual(unlocked.accountId, snapshot.accountId)

        // A message on a connection without a session asks Firefox to set one up again.
        Legacy.clear(connectionID: connection)
        let staleMessage = try XCTUnwrap(Legacy.encrypt(try JSONSerialization.data(withJSONObject: [
            "command": "getBiometricsStatus", "userId": snapshot.accountId, "messageId": 3, "timestamp": now(),
        ]), secret: secret))
        let stale = try reply(to: staleMessage)
        XCTAssertEqual(stale["command"] as? String, "invalidateEncryption")

        client.invalidateSession()
        try await client.logout()
    }

    // MARK: Extension side

    private func now() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    private func reply(to message: Any) throws -> [String: Any] {
        let outer = try JSONSerialization.data(withJSONObject: ["appId": appID, "message": message])
        let data = try XCTUnwrap(Legacy.process(outer, connectionID: connection), "no reply")
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    /// Sends an encrypted command and validates the reply the way the extension's onMessage does.
    private func encryptedCall(_ message: [String: Any], secret: Data) throws -> [String: Any] {
        var message = message
        message["timestamp"] = now()
        let plaintext = try JSONSerialization.data(withJSONObject: message)
        let outer = try reply(to: try XCTUnwrap(Legacy.encrypt(plaintext, secret: secret)))
        XCTAssertEqual(outer["appId"] as? String, appID, "Firefox ignores replies for other app ids")
        XCTAssertNil(outer["command"], "An encrypted reply must not carry a top-level command")
        let encString = try XCTUnwrap(outer["message"] as? [String: Any])
        XCTAssertEqual(encString["encryptionType"] as? Int, 2)
        let decrypted = try XCTUnwrap(Legacy.decrypt(encString, secret: secret), "reply must decrypt")
        let inner = try XCTUnwrap(JSONSerialization.jsonObject(with: decrypted) as? [String: Any])
        XCTAssertEqual(inner["messageId"] as? Int, message["messageId"] as? Int)
        XCTAssertEqual(inner["command"] as? String, message["command"] as? String)
        let stamp = try XCTUnwrap((inner["timestamp"] as? NSNumber)?.int64Value)
        XCTAssertLessThan(abs(stamp - now()), 10_000, "Firefox discards replies older than 10 s")
        return inner
    }

    private func rsaKeyPair() throws -> (SecKey, String) {
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                         kSecAttrKeySizeInBits as String: 2048]
        let privateKey = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, nil))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        let pkcs1 = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil) as Data?)
        // The extension sends SubjectPublicKeyInfo DER (WebCrypto "spki").
        let header: [UInt8] = [0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                               0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00]
        return (privateKey, (Data(header) + pkcs1).base64EncodedString())
    }
}
