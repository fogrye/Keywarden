import CommonCrypto
import Foundation
import LocalAuthentication
import Security

// Each authenticated native port owns its encryption and replay state.
enum Legacy {
    private static let mutex = NSLock()
    nonisolated(unsafe) private static var channels: [UInt64: Channel] = [:]
    static let maxMessage = 1_048_576
    static let validityMilliseconds: Int64 = 10_000

    struct Channel {
        let appID: String
        let userID: String
        let secret: Data
        var seen: [Int: Int64] = [:]
    }

    static func clear(connectionID: UInt64) {
        mutex.lock()
        channels.removeValue(forKey: connectionID)
        mutex.unlock()
    }

    static func timestamp() -> Int64 { Int64(Date().timeIntervalSince1970 * 1_000) }

    static func current(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              let integer = Int64(number.stringValue) else { return false }
        let now = timestamp()
        return integer >= now - validityMilliseconds && integer <= now + validityMilliseconds
    }

    static func messageID(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              let integer = Int(number.stringValue), integer >= 0 else { return nil }
        return integer
    }

    static func process(_ input: Data, connectionID: UInt64) -> Data? {
        guard let outer = try? JSONSerialization.jsonObject(with: input) as? [String: Any],
              let appID = outer["appId"] as? String, !appID.isEmpty,
              let message = outer["message"] as? [String: Any] else { return nil }

        if let command = message["command"] as? String {
            guard command == "setupEncryption", current(message["timestamp"]),
                  let user = message["userId"] as? String, UUID(uuidString: user) != nil else { return nil }
            // Like Bitwarden Desktop, tell the extension when its account is not the one signed in
            // here instead of letting its request time out. The channel itself carries no secret:
            // unlocking still requires the Firefox opt-in and a fresh Touch ID authorization.
            guard BiometricCoordinator.shared.identity(user, browser: false) != nil else {
                biometricLog.notice("Browser: setupEncryption for an account not signed in here → wrongUserId")
                return json(["command": "wrongUserId", "appId": appID])
            }
            guard let publicKey = message["publicKey"] as? String,
                  let spki = Data(base64Encoded: publicKey),
                  let key = rsaPublicKey(spki) else { return nil }
            var secret = Data(count: 64)
            let result = secret.withUnsafeMutableBytes { bytes in
                SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
            }
            guard result == errSecSuccess,
                  let encrypted = SecKeyCreateEncryptedData(key, .rsaEncryptionOAEPSHA1,
                                                             secret as CFData, nil) as Data? else { return nil }
            mutex.lock()
            channels[connectionID] = Channel(appID: appID, userID: user, secret: secret)
            mutex.unlock()
            biometricLog.info("Browser: secure channel set up (connection \(connectionID))")
            return json(["appId": appID, "command": "setupEncryption", "messageId": -1,
                         "sharedSecret": encrypted.base64EncodedString()])
        }

        mutex.lock()
        let existing = channels[connectionID]
        mutex.unlock()
        // A missing or undecryptable session makes the extension set up a new channel.
        guard let channel = existing, channel.appID == appID else {
            biometricLog.notice("Browser: message without a session → invalidateEncryption")
            return json(["command": "invalidateEncryption", "appId": appID])
        }
        guard let plaintext = decrypt(message, secret: channel.secret) else {
            clear(connectionID: connectionID)
            biometricLog.notice("Browser: message failed to decrypt → invalidateEncryption")
            return json(["command": "invalidateEncryption", "appId": appID])
        }
        guard let request = try? JSONSerialization.jsonObject(with: plaintext) as? [String: Any],
              current(request["timestamp"]),
              let user = request["userId"] as? String, user == channel.userID,
              let id = messageID(request["messageId"]),
              let command = request["command"] as? String else {
            biometricLog.notice("Browser: dropped a request (stale timestamp, other account or malformed)")
            return nil
        }

        mutex.lock()
        guard var current = channels[connectionID], current.appID == appID else {
            mutex.unlock()
            return nil
        }
        let oldest = timestamp() - validityMilliseconds
        current.seen = current.seen.filter { $0.value >= oldest }
        guard current.seen[id] == nil else { mutex.unlock(); return nil }
        current.seen[id] = timestamp()
        channels[connectionID] = current
        mutex.unlock()

        biometricLog.info("Browser: \(command, privacy: .public) (message \(id), connection \(connectionID))")
        var response: [String: Any] = ["command": command, "messageId": id]
        switch command {
        case "getBiometricsStatus":
            response["response"] = biometricStatus()
        case "getBiometricsStatusForUser":
            let status = biometricStatus()
            // 8 = NotEnabledInConnectedDesktopApp: Touch ID works here but Firefox unlock is off.
            response["response"] = status == 0 && BiometricCoordinator.shared.status(user) != 0 ? 8 : status
        case "authenticateWithBiometrics":
            response["response"] = BiometricCoordinator.shared.identity(user, browser: true) != nil
                && BiometricCoordinator.shared.approved(connection: connectionID)
        case "unlockWithBiometricsForUser":
            if let data = BiometricCoordinator.shared.readAuthorizedEnrollment(
                id: user, connection: connectionID, browser: true),
               let record = try? JSONDecoder().decode(LegacyEnrollment.self, from: data),
               record.accountId.caseInsensitiveCompare(user) == .orderedSame,
               record.server == BiometricCoordinator.shared.identity(user, browser: true)?.server {
                response["response"] = true
                response["userKeyB64"] = record.keyB64
            } else {
                response["response"] = false
            }
        default: return nil
        }
        // Stamp the reply when it is sent, not when the request arrived: Firefox discards replies more
        // than 10 seconds old, and a Touch ID prompt can easily take longer than that.
        response["timestamp"] = timestamp()
        biometricLog.info("Browser: \(command, privacy: .public) → \(String(describing: response["response"] ?? "nil"), privacy: .public)")
        guard let reply = json(response), let ciphertext = encrypt(reply, secret: channel.secret) else {
            return nil
        }
        return json(["appId": appID, "messageId": id, "message": ciphertext])
    }

    static func json(_ object: [String: Any]) -> Data? {
        try? JSONSerialization.data(withJSONObject: object)
    }

    static func biometricStatus() -> Int {
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return 0
        }
        if let error, error.domain == LAError.errorDomain,
           LAError.Code(rawValue: error.code) == .biometryLockout {
            return 1
        }
        return 2
    }

    // DER is parsed without accepting BER indefinite lengths, nonminimal encodings, trailing
    // bytes or non-RSA algorithm identifiers. SecKeyCreateWithData expects PKCS#1, not SPKI.
    struct DER {
        let data: Data
        var offset = 0

        mutating func item(_ tag: UInt8) -> Data? {
            guard offset < data.count, data[offset] == tag else { return nil }
            offset += 1
            guard offset < data.count else { return nil }
            let first = Int(data[offset]); offset += 1
            var length = first
            if first & 0x80 != 0 {
                let count = first & 0x7f
                guard count > 0, count <= 4, count <= data.count - offset,
                      data[offset] != 0 else { return nil }
                length = 0
                for _ in 0..<count {
                    guard length <= (Int.max >> 8) else { return nil }
                    length = (length << 8) | Int(data[offset]); offset += 1
                }
                guard length >= 128 else { return nil }
            }
            guard length <= data.count - offset else { return nil }
            defer { offset += length }
            return data.subdata(in: offset..<(offset + length))
        }

        var finished: Bool { offset == data.count }
    }

    static func rsaPublicKey(_ spki: Data) -> SecKey? {
        // rsaEncryption OID 1.2.840.113549.1.1.1, with the mandatory NULL parameters.
        let oid = Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
        var root = DER(data: spki)
        guard let content = root.item(0x30), root.finished else { return nil }
        var fields = DER(data: content)
        guard let algorithm = fields.item(0x30), let bits = fields.item(0x03), fields.finished,
              bits.first == 0 else { return nil }
        var parameters = DER(data: algorithm)
        guard parameters.item(0x06) == oid, parameters.item(0x05)?.isEmpty == true,
              parameters.finished else { return nil }
        let pkcs1 = Data(bits.dropFirst())
        var key = DER(data: pkcs1)
        guard let integers = key.item(0x30), key.finished else { return nil }
        var numbers = DER(data: integers)
        guard let modulus = numbers.item(0x02), let exponent = numbers.item(0x02),
              numbers.finished, exponent == Data([0x01, 0x00, 0x01]) else { return nil }
        // DER INTEGER: positive, minimal, exactly 2048 significant bits.
        let validModulus = modulus.count == 257 && modulus[0] == 0 && modulus[1] >= 0x80
        guard validModulus else { return nil }
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                         kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                                         kSecAttrKeySizeInBits as String: 2048]
        guard let publicKey = SecKeyCreateWithData(pkcs1 as CFData, attributes as CFDictionary, nil),
              SecKeyGetBlockSize(publicKey) == 256,
              SecKeyIsAlgorithmSupported(publicKey, .encrypt, .rsaEncryptionOAEPSHA1)
        else { return nil }
        return publicKey
    }

    static func mac(_ data: Data, key: Data) -> Data {
        var digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        digest.withUnsafeMutableBytes { result in
            key.withUnsafeBytes { secret in
                data.withUnsafeBytes { bytes in
                    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), secret.baseAddress, secret.count,
                           bytes.baseAddress, bytes.count, result.baseAddress)
                }
            }
        }
        return digest
    }

    static func crypt(_ input: Data, key: Data, iv: Data, operation: CCOperation) -> Data? {
        var output = Data(count: input.count + kCCBlockSizeAES128)
        var written = 0
        let status = output.withUnsafeMutableBytes { destination in
            input.withUnsafeBytes { source in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                                keyBytes.baseAddress, kCCKeySizeAES256, ivBytes.baseAddress,
                                source.baseAddress, source.count, destination.baseAddress,
                                destination.count, &written)
                    }
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        output.count = written
        return output
    }

    static func components(_ value: [String: Any]) -> (Data, Data, Data)? {
        guard let encryptedString = value["encryptedString"] as? String,
              let type = value["encryptionType"] as? Int, type == 2,
              encryptedString.hasPrefix("2.") else { return nil }
        let pieces = encryptedString.dropFirst(2).split(separator: "|", omittingEmptySubsequences: false)
        guard pieces.count == 3,
              let iv = Data(base64Encoded: String(pieces[0])), iv.count == kCCBlockSizeAES128,
              let ciphertext = Data(base64Encoded: String(pieces[1])), !ciphertext.isEmpty,
              ciphertext.count % kCCBlockSizeAES128 == 0,
              let tag = Data(base64Encoded: String(pieces[2])), tag.count == Int(CC_SHA256_DIGEST_LENGTH)
        else { return nil }
        return (iv, ciphertext, tag)
    }

    static func decrypt(_ value: [String: Any], secret: Data) -> Data? {
        guard secret.count == 64, let (iv, ciphertext, tag) = components(value) else { return nil }
        let expected = mac(iv + ciphertext, key: Data(secret.suffix(32)))
        var difference: UInt8 = 0
        for index in 0..<expected.count { difference |= expected[index] ^ tag[index] }
        guard difference == 0 else { return nil }
        return crypt(ciphertext, key: Data(secret.prefix(32)), iv: iv, operation: CCOperation(kCCDecrypt))
    }

    static func encrypt(_ plaintext: Data, secret: Data) -> [String: Any]? {
        guard secret.count == 64 else { return nil }
        var iv = Data(count: kCCBlockSizeAES128)
        guard iv.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess,
              let ciphertext = crypt(plaintext, key: Data(secret.prefix(32)), iv: iv,
                                     operation: CCOperation(kCCEncrypt)) else { return nil }
        let tag = mac(iv + ciphertext, key: Data(secret.suffix(32)))
        let encoded = "2.\(iv.base64EncodedString())|\(ciphertext.base64EncodedString())|\(tag.base64EncodedString())"
        return ["encryptedString": encoded, "encryptionType": 2,
                "data": ciphertext.base64EncodedString(), "iv": iv.base64EncodedString(),
                "mac": tag.base64EncodedString()]
    }
}

private struct LegacyEnrollment: Decodable {
    let accountId: String
    let server: String
    let keyB64: String
}

@_cdecl("bw_legacy_process")
func bwLegacyProcess(_ connectionID: UInt64, _ input: UnsafePointer<UInt8>?, _ length: Int,
                     _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int) -> Int32 {
    guard length >= 0, length <= Legacy.maxMessage, capacity >= 0 else { return -1 }
    guard let input, length > 0 else { return -1 }
    guard let output, capacity > 0 else { return 0 }
    guard let reply = Legacy.process(Data(bytes: input, count: length), connectionID: connectionID),
          reply.count <= capacity, reply.count <= Int(Int32.max) else { return 0 }
    reply.withUnsafeBytes { bytes in
        output.update(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: reply.count)
    }
    return Int32(reply.count)
}
