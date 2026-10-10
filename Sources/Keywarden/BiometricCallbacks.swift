import Foundation
import os

struct StoredEnrollment: Decodable {
    let accountId: String
    let server: String
    let keyId: String?
    let keyB64: String
}

@_silgen_name("bw_app_generation")
private func currentAccountGeneration() -> UInt64

@_cdecl("bw_biometric")
func bwBiometric(_ connection: UInt64, _ request: UInt64, _ generation: UInt64,
                 _ action: Int32, _ userPointer: UnsafePointer<CChar>?,
                 _ output: UnsafeMutablePointer<UInt8>?, _ capacity: Int) -> Int32 {
    guard generation == currentAccountGeneration() else { return 0 }
    let user = userPointer.flatMap { String(validatingCString: $0) }
    let coordinator = BiometricCoordinator.shared
    switch action {
    case 0: return user.map { coordinator.status($0) } ?? 3
    case 1:
        return coordinator.approved(connection: connection) ? 1 : 0
    case 2:
        guard let user, let output, capacity > 0,
              let identity = coordinator.identity(user, browser: true),
              let data = coordinator.readAuthorizedEnrollment(id: user, connection: connection, browser: true),
              let record = try? JSONDecoder().decode(StoredEnrollment.self, from: data),
              record.accountId.caseInsensitiveCompare(user) == .orderedSame,
              record.server == identity.server,
              let encoded = record.keyB64.data(using: .utf8),
              encoded.count <= capacity, encoded.count <= Int(Int32.max),
              generation == currentAccountGeneration(),
              coordinator.identity(user, browser: true)?.hash == identity.hash else { return 0 }
        encoded.withUnsafeBytes { bytes in
            if let base = bytes.baseAddress {
                output.update(from: base.assumingMemoryBound(to: UInt8.self), count: encoded.count)
            }
        }
        return Int32(encoded.count)
    default: return 0
    }
}

@_cdecl("bw_connection_cancel")
func bwConnectionCancel(_ connection: UInt64) {
    BiometricCoordinator.shared.cancel(connection)
    Legacy.clear(connectionID: connection)
}

private let rustLog = Logger(subsystem: "xyz.kuvshynov.Keywarden", category: "core")

/// Diagnostics from the Rust core. Callers pass status text and error causes, never secrets.
@_cdecl("bw_log")
func bwLog(_ message: UnsafePointer<CChar>?) {
    guard let message, let text = String(validatingCString: message) else { return }
    rustLog.notice("\(text, privacy: .public)")
}
