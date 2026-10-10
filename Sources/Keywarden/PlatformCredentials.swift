import Foundation
import LocalAuthentication
import Security

enum CredentialError: Error { case keychain(OSStatus), invalid }

enum PlatformCredentials {
    static let tokens = "xyz.kuvshynov.Keywarden.tokens"
    static let biometric = "xyz.kuvshynov.Keywarden.biometric"
    static let pin = "xyz.kuvshynov.Keywarden.pin"
    /// Email forwarder API keys and tokens for the username generator.
    static let forwarder = "xyz.kuvshynov.Keywarden.forwarder"
    /// Security settings and the per-account browser unlock opt-in. UserDefaults is writable by any
    /// process running as the user; these items are not. Never reachable from `bw_credentials`.
    static let settings = "xyz.kuvshynov.Keywarden.settings"
    static let browserUnlock = "xyz.kuvshynov.Keywarden.browserUnlock"

    private static func query(_ service: String, _ account: String) -> [String: Any]? {
        guard account.utf8.count == 64,
              account.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }) else { return nil }
        return [kSecClass as String: kSecClassGenericPassword,
                kSecUseDataProtectionKeychain as String: true,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: false]
    }

    #if DEBUG
    /// Test runs with an isolated namespace keep credentials in memory instead of the login Keychain.
    private static let isolated: Bool = {
        let environment = ProcessInfo.processInfo.environment
        return (environment["BW_TEST_NAMESPACE"] ?? environment["BW_UI_TEST_NAMESPACE"]).flatMap(UUID.init) != nil
    }()
    nonisolated(unsafe) private static var memory: [String: Data] = [:]
    private static let memoryLock = NSLock()
    private static func inMemory<T>(_ body: (inout [String: Data]) -> T) -> T {
        memoryLock.lock(); defer { memoryLock.unlock() }
        return body(&memory)
    }
    #endif

    static func token(_ account: String) throws -> Data? { try read(tokens, account) }

    static func read(_ service: String, _ account: String, context: LAContext? = nil) throws -> Data? {
        #if DEBUG
        if isolated { return inMemory { $0["\(service)/\(account)"] } }
        #endif
        guard var attributes = query(service, account) else { throw CredentialError.invalid }
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context { attributes[kSecUseAuthenticationContext as String] = context }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw CredentialError.keychain(status) }
        return data
    }

    static func store(_ data: Data, service: String, account: String) throws {
        guard let attributes = query(service, account), !data.isEmpty else { throw CredentialError.invalid }
        #if DEBUG
        if isolated { inMemory { $0["\(service)/\(account)"] = data }; return }
        #endif
        let old = SecItemUpdate(attributes as CFDictionary,
                                [kSecValueData as String: data] as CFDictionary)
        if old == errSecSuccess { return }
        guard old == errSecItemNotFound else { throw CredentialError.keychain(old) }
        var addition = attributes
        addition[kSecValueData as String] = data
        if service == biometric {
            var error: Unmanaged<CFError>?
            guard let control = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error) else {
                throw CredentialError.invalid
            }
            addition[kSecAttrAccessControl as String] = control
        } else if service == settings || service == browserUnlock {
            // Read at launch, which can happen before the screen is unlocked.
            addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        } else {
            addition[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        let result = SecItemAdd(addition as CFDictionary, nil)
        guard result == errSecSuccess else { throw CredentialError.keychain(result) }
    }

    static func delete(_ service: String, _ account: String) throws {
        guard let attributes = query(service, account) else { throw CredentialError.invalid }
        #if DEBUG
        if isolated { inMemory { $0["\(service)/\(account)"] = nil }; return }
        #endif
        let status = SecItemDelete(attributes as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw CredentialError.keychain(status) }
    }

    static func enrolled(_ account: String) -> Bool {
        #if DEBUG
        if isolated { return inMemory { $0["\(biometric)/\(account)"] != nil } }
        #endif
        guard var attributes = query(biometric, account) else { return false }
        attributes[kSecReturnAttributes as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        // An existence check must never show Touch ID. Without this, every status refresh and every
        // Firefox status poll prompted, and those prompts fought the one that actually unlocks.
        let silent = LAContext()
        silent.interactionNotAllowed = true
        attributes[kSecUseAuthenticationContext as String] = silent
        var result: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &result)
        // "Interaction not allowed" means the item exists but would need authentication.
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }
}

// Rust selects the account hash. The ABI never accepts an arbitrary Keychain service or path.
// Actions: 0 read / 1 store / 2 delete tokens, 3 store / 4 delete Touch ID key, 5 store / 6 delete / 7 read PIN.
private func service(_ action: Int32) -> String {
    switch action {
    case 0, 1, 2: PlatformCredentials.tokens
    case 3, 4: PlatformCredentials.biometric
    default: PlatformCredentials.pin
    }
}

@_cdecl("bw_credentials")
func bwCredentials(_ action: Int32, _ account: UnsafePointer<CChar>?,
                   _ input: UnsafePointer<UInt8>?, _ inputLength: Int,
                   _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int) -> Int32 {
    guard let account, let hash = String(validatingCString: account),
          inputLength >= 0, capacity >= 0 else { return -1 }
    do {
        switch action {
        case 0, 7:
            guard let data = try PlatformCredentials.read(action == 0 ? PlatformCredentials.tokens : PlatformCredentials.pin,
                                                          hash) else { return 0 }
            guard let output, data.count <= capacity, data.count <= Int(Int32.max) else { return -1 }
            data.withUnsafeBytes { bytes in
                if let pointer = bytes.baseAddress { output.update(from: pointer.assumingMemoryBound(to: UInt8.self), count: data.count) }
            }
            return Int32(data.count)
        case 1, 3, 5:
            guard let input, inputLength > 0, inputLength <= 1024 * 1024 else { return -1 }
            try PlatformCredentials.store(Data(bytes: input, count: inputLength),
                                          service: service(action), account: hash)
            return 1
        case 2, 4, 6:
            try PlatformCredentials.delete(service(action), hash)
            return 1
        default: return -1
        }
    } catch { return -1 }
}
