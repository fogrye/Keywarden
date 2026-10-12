import Foundation

/// Serializes calls into the Rust account core. Every request runs on one background queue.
@MainActor
final class SDKClient {
    static let shared = SDKClient()
    private let queue = DispatchQueue(label: "xyz.kuvshynov.Keywarden.sdk", qos: .userInitiated)

    private init() {}

    func status() async throws -> VaultStatus { try await invoke(Request(op: "status")) }
    func login(email: String, password: String, server: String) async throws -> VaultSnapshot {
        try await invoke(Request(op: "login", email: email, password: password, server: server))
    }
    func unlock(password: String) async throws -> VaultSnapshot {
        try await invoke(Request(op: "unlock", password: password))
    }
    func unlock(pin: String) async throws -> VaultSnapshot {
        try await invoke(Request(op: "unlockPin", pin: pin))
    }
    func enrollPin(_ pin: String) async throws { let _: EmptyReply = try await invoke(Request(op: "enrollPin", pin: pin)) }
    func disablePin() async throws { let _: EmptyReply = try await invoke(Request(op: "disablePin")) }
    func sync() async throws -> VaultSnapshot { try await invoke(Request(op: "sync")) }
    func item(id: String) async throws -> ItemDetail { try await invoke(Request(op: "item", id: id)) }
    func totp(id: String) async throws -> TotpCode { try await invoke(Request(op: "totp", id: id)) }
    func save(_ item: ItemData) async throws -> MutationResult {
        try await invoke(Request(op: "saveItem", item: item))
    }
    func organize(id: String, favorite: Bool, folderId: String?) async throws -> MutationResult {
        try await invoke(Request(op: "organize", id: id, favorite: favorite, folderId: .some(folderId)))
    }
    func delete(id: String, permanent: Bool) async throws -> MutationResult {
        try await invoke(Request(op: "deleteItem", id: id, permanent: permanent))
    }
    func archive(id: String, archived: Bool) async throws -> MutationResult {
        try await invoke(Request(op: "archiveItem", id: id, archived: archived))
    }
    func restore(id: String) async throws -> MutationResult {
        try await invoke(Request(op: "restoreItem", id: id))
    }
    /// Decrypts an attachment and writes it to `url`. The file bytes never pass through this API.
    func downloadAttachment(id: String, attachmentId: String, to url: URL) async throws {
        let _: EmptyReply = try await invoke(Request(op: "attachmentDownload", id: id, attachmentId: attachmentId, path: url.path))
    }
    /// Encrypts the file at `url` and attaches it to the saved item.
    func uploadAttachment(id: String, from url: URL) async throws -> MutationResult {
        try await invoke(Request(op: "attachmentUpload", id: id, path: url.path))
    }
    func deleteAttachment(id: String, attachmentId: String) async throws -> MutationResult {
        try await invoke(Request(op: "attachmentDelete", id: id, attachmentId: attachmentId))
    }
    /// Checks the master password only, so the save panel can follow. Nothing is written.
    func verifyMasterPassword(_ masterPassword: String) async throws {
        let _: ExportVerification = try await invoke(Request(op: "exportVault", format: "json", masterPassword: masterPassword))
    }
    /// Re-checks the master password, then encrypts (if asked) and writes the vault to `url`. Only
    /// counts come back; the contents never pass through this API.
    func exportVault(format: String, filePassword: String?, masterPassword: String, to url: URL) async throws -> ExportSummary {
        try await invoke(Request(op: "exportVault", path: url.path, format: format,
                                 masterPassword: masterPassword, filePassword: filePassword))
    }
    /// Reads and, if needed, decrypts the file at `url` inside the core, which holds the items in
    /// memory. Only counts come back. Throws `passwordRequired` or `invalidFilePassword` for
    /// password-protected files.
    func prepareImport(from url: URL, filePassword: String?) async throws -> ImportPreview {
        try await invoke(Request(op: "importPrepare", path: url.path, filePassword: filePassword))
    }
    /// Encrypts the held items, uploads them and syncs.
    func commitImport() async throws -> ImportCommit { try await invoke(Request(op: "importCommit")) }
    func discardImport() async { let _: EmptyReply? = try? await invoke(Request(op: "importDiscard")) }
    func saveFolder(id: String?, name: String) async throws -> MutationResult {
        try await invoke(Request(op: "saveFolder", id: id, name: name))
    }
    func deleteFolder(id: String) async throws -> MutationResult {
        try await invoke(Request(op: "deleteFolder", id: id))
    }
    func lock() async throws { let _: EmptyReply = try await invoke(Request(op: "lock")) }
    func logout() async throws { let _: EmptyReply = try await invoke(Request(op: "logout")) }
    func generate(options: [String: Any]) async throws -> String { try await generate(op: "generate", options: options) }
    /// Forwarded aliases contact the chosen service with the token in `options`, so errors are shown but never logged.
    func generateUsername(options: [String: Any]) async throws -> String {
        try await generate(op: "generateUsername", options: options)
    }
    private func generate(op: String, options: [String: Any]) async throws -> String {
        guard JSONSerialization.isValidJSONObject(options), options["op"] == nil else {
            throw SDKClientError.encoding
        }
        let body = try JSONSerialization.data(withJSONObject: options.merging(["op": op]) { _, new in new })
        let value: GeneratedSecret = try await invokeData(body)
        return value.text
    }

    /// zxcvbn score 0...4 from the SDK, computed locally. `inputs` (item name, username) are penalized.
    func passwordStrength(password: String, email: String, inputs: [String]) async throws -> Int {
        let body = try JSONSerialization.data(withJSONObject: ["op": "passwordStrength", "password": password,
                                                               "email": email, "inputs": inputs])
        let value: PasswordScore = try await invokeData(body)
        return value.score
    }

    // The priority path never waits for the request queue: late native results cannot republish a key.
    @discardableResult nonisolated func invalidateSession() -> UInt64 { bwAppInvalidateSession() }
    func generation() -> UInt64 { bwAppGeneration() }
    func enrollBiometrics(generation: UInt64) async throws {
        let result = await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: bwAppEnrollBiometrics(generation)) }
        }
        guard result == 1 else { throw VaultError(code: "storageUnavailable", message: String(localized: "Touch ID enrollment failed.")) }
    }

    func unlockBiometrics(authorization: Data, generation: UInt64) async throws -> VaultSnapshot {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                var bytes = [UInt8](authorization)
                defer { bytes.withUnsafeMutableBufferPointer { $0.initialize(repeating: 0) } }
                let output = bytes.withUnsafeBufferPointer { pointer in
                    bwAppUnlockWithKey(pointer.baseAddress, pointer.count, generation)
                }
                guard let output else {
                    continuation.resume(throwing: SDKClientError.backend)
                    return
                }
                defer { bwAppResponseFree(output) }
                do {
                    let reply = try JSONDecoder().decode(BackendReply<VaultSnapshot>.self,
                                                         from: Data(bytes: output, count: strlen(output)))
                    guard reply.ok, let value = reply.value else {
                        throw reply.error ?? VaultError(code: "invalidResponse", message: String(localized: "Touch ID unlock failed."))
                    }
                    continuation.resume(returning: value)
                } catch { continuation.resume(throwing: error) }
            }
        }
    }

    private func invoke<Value: Decodable & Sendable>(_ request: Request) async throws -> Value {
        try await invokeData(JSONEncoder().encode(request))
    }

    private func invokeData<Value: Decodable & Sendable>(_ body: Data) async throws -> Value {
        guard body.count <= 1024 * 1024 else { throw SDKClientError.encoding }
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
                var input = [UInt8](body)
                input.append(0)
                defer { input.withUnsafeMutableBufferPointer { $0.initialize(repeating: 0) } }
                do {
                    let reply: BackendReply<Value> = try input.withUnsafeBufferPointer { bytes in
                        guard let base = bytes.baseAddress else { throw SDKClientError.encoding }
                        return try base.withMemoryRebound(to: CChar.self, capacity: bytes.count) { pointer in
                            guard let output = bwAppRequest(pointer) else { throw SDKClientError.backend }
                            defer { bwAppResponseFree(output) }
                            return try JSONDecoder().decode(BackendReply<Value>.self,
                                                            from: Data(bytes: output, count: strlen(output)))
                        }
                    }
                    if reply.ok, let value = reply.value { continuation.resume(returning: value) }
                    else {
                        let missing = VaultError(code: "invalidResponse", message: String(localized: "The backend did not return a value."))
                        continuation.resume(throwing: reply.error ?? missing)
                    }
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
}

private struct Request: Encodable {
    let op: String
    var email: String? = nil
    var password: String? = nil
    var server: String? = nil
    var id: String? = nil
    var name: String? = nil
    var item: ItemData? = nil
    var favorite: Bool? = nil
    /// Double optional: `.some(nil)` encodes an explicit `null` ("no folder").
    var folderId: String?? = nil
    var permanent: Bool? = nil
    var pin: String? = nil
    var archived: Bool? = nil
    var attachmentId: String? = nil
    var path: String? = nil
    var format: String? = nil
    var masterPassword: String? = nil
    var filePassword: String? = nil

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(op, forKey: .op)
        try container.encodeIfPresent(email, forKey: .email)
        try container.encodeIfPresent(password, forKey: .password)
        try container.encodeIfPresent(server, forKey: .server)
        try container.encodeIfPresent(id, forKey: .id)
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(item, forKey: .item)
        try container.encodeIfPresent(favorite, forKey: .favorite)
        if let folderId { try container.encode(folderId, forKey: .folderId) }
        try container.encodeIfPresent(permanent, forKey: .permanent)
        try container.encodeIfPresent(pin, forKey: .pin)
        try container.encodeIfPresent(archived, forKey: .archived)
        try container.encodeIfPresent(attachmentId, forKey: .attachmentId)
        try container.encodeIfPresent(path, forKey: .path)
        try container.encodeIfPresent(format, forKey: .format)
        try container.encodeIfPresent(masterPassword, forKey: .masterPassword)
        try container.encodeIfPresent(filePassword, forKey: .filePassword)
    }
    private enum CodingKeys: String, CodingKey {
        case op, email, password, server, id, name, item, favorite, folderId, permanent, pin, archived, attachmentId, path
        case format, masterPassword, filePassword
    }
}
private struct EmptyReply: Decodable, Sendable {}
private struct ExportVerification: Decodable, Sendable { let verified: Bool }
private struct PasswordScore: Decodable, Sendable { let score: Int }
private struct GeneratedSecret: Decodable, Sendable { let text: String }
private struct BackendReply<Value: Decodable>: Decodable {
    let ok: Bool
    let value: Value?
    let error: VaultError?
}

enum SDKClientError: LocalizedError {
    case encoding, backend
    var errorDescription: String? {
        switch self {
        case .encoding: String(localized: "Could not encode the SDK request.")
        case .backend: String(localized: "The SDK did not return a response.")
        }
    }
}

@_silgen_name("bw_app_request")
private func bwAppRequest(_ input: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("bw_app_response_free")
private func bwAppResponseFree(_ response: UnsafeMutablePointer<CChar>)
@_silgen_name("bw_app_invalidate_session")
private func bwAppInvalidateSession() -> UInt64
@_silgen_name("bw_app_generation")
private func bwAppGeneration() -> UInt64
@_silgen_name("bw_app_enroll_biometrics")
private func bwAppEnrollBiometrics(_ generation: UInt64) -> Int32
@_silgen_name("bw_app_unlock_with_key")
private func bwAppUnlockWithKey(_ key: UnsafePointer<UInt8>?, _ length: Int,
                                _ generation: UInt64) -> UnsafeMutablePointer<CChar>?
