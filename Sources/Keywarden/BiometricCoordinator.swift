import Foundation
import LocalAuthentication
import os

let biometricLog = Logger(subsystem: "xyz.kuvshynov.Keywarden", category: "touchid")

final class BiometricCoordinator: @unchecked Sendable {
    static let shared = BiometricCoordinator()
    private let lock = NSLock()
    private var contextByConnection: [UInt64: LAContext] = [:]
    /// The browser behind each native-messaging connection, named in its Touch ID prompts.
    private var requesters: [UInt64: String] = [:]
    /// The app's own unlock, as opposed to a browser connection.
    static let appConnection: UInt64 = 0
    private var account: (id: String, hash: String, server: String, email: String)?
    private var browserEnabled = false
    /// Why the last authorized read returned nothing, for the app's own unlock screen.
    private(set) var lastFailure: String?
    private init() {}

    func configure(id: String?, hash: String?, server: String, email: String) {
        lock.lock(); defer { lock.unlock() }
        if let id, let hash { account = (id, hash, server, email) }
        else { account = nil; browserEnabled = false }
    }

    func setBrowserEnabled(_ enabled: Bool) {
        lock.lock(); browserEnabled = enabled; lock.unlock()
    }

    func identity(_ id: String, browser: Bool) -> (hash: String, server: String, email: String)? {
        lock.lock(); defer { lock.unlock() }
        guard let account, account.id.caseInsensitiveCompare(id) == .orderedSame,
              !browser || browserEnabled else { return nil }
        return (account.hash, account.server, account.email)
    }
    func currentBrowserIdentity() -> (hash: String, server: String, email: String)? {
        lock.lock(); defer { lock.unlock() }
        guard browserEnabled, let account else { return nil }
        return (account.hash, account.server, account.email)
    }

    func register(connection: UInt64, requester: String) {
        lock.lock(); requesters[connection] = requester; lock.unlock()
    }

    func cancel(_ connection: UInt64? = nil) {
        lock.lock()
        let contexts: [LAContext]
        if let connection {
            contexts = contextByConnection.removeValue(forKey: connection).map { [$0] } ?? []
            requesters.removeValue(forKey: connection)
        }
        else { contexts = Array(contextByConnection.values); contextByConnection.removeAll() }
        lock.unlock()
        contexts.forEach { $0.invalidate() }
    }

    func status(_ id: String) -> Int32 {
        guard let identity = identity(id, browser: true), PlatformCredentials.enrolled(identity.hash) else { return 3 }
        let context = LAContext()
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) { return 0 }
        if let error, error.domain == LAError.errorDomain,
           LAError.Code(rawValue: error.code) == .biometryLockout { return 1 }
        return 2
    }

    /// macOS shows the reason as "<app> is trying to <reason>", so each one names who gets what.
    func reason(connection: UInt64, email: String, server: String, releasesKey: Bool) -> String {
        // macOS shows these as "Keywarden is trying to <reason>." in the user's language, so each
        // translation must complete that sentence and keep every placeholder.
        guard connection != Self.appConnection else {
            return String(localized: "unlock \(email) (\(server))", comment: "Touch ID prompt: “Keywarden is trying to …”")
        }
        let browser = requesters[connection] ?? String(localized: "an unidentified app")
        return releasesKey
            ? String(localized: "send the vault key for \(email) to \(browser)", comment: "Touch ID prompt: “Keywarden is trying to …”")
            : String(localized: "confirm \(email) for \(browser)", comment: "Touch ID prompt: “Keywarden is trying to …”")
    }

    /// Browser requests take the prompt only when nothing else holds it; the app's own unlock
    /// cancels any browser prompt, so a pending browser request can never pass as the app's.
    /// Call with `lock` held. Returns nil when refused, otherwise the prompts to cancel once
    /// `lock` is released.
    func claimPrompt(_ context: LAContext, connection: UInt64) -> [LAContext]? {
        var displaced: [LAContext] = []
        if connection == Self.appConnection {
            displaced = Array(contextByConnection.values)
            contextByConnection.removeAll()
        } else if !contextByConnection.isEmpty {
            return nil
        }
        contextByConnection[connection] = context
        return displaced
    }

    /// Removes `context` unless a newer prompt has already taken its connection's slot.
    func release(_ context: LAContext, connection: UInt64) {
        lock.lock()
        if contextByConnection[connection] === context { contextByConnection.removeValue(forKey: connection) }
        lock.unlock()
        context.invalidate()
    }

    /// Touch ID confirmation for a browser connection (`authenticateWithBiometrics`).
    func approved(connection: UInt64) -> Bool {
        guard connection != Self.appConnection, let identity = currentBrowserIdentity() else { return false }
        lock.lock()
        let reason = reason(connection: connection, email: identity.email, server: identity.server, releasesKey: false)
        lock.unlock()
        return confirm(connection: connection, reason: reason)
    }

    /// Touch ID confirmation for the app itself, such as turning Touch ID on.
    func approvedInApp(reason: String) -> Bool {
        confirm(connection: Self.appConnection, reason: reason)
    }

    private func confirm(connection: UInt64, reason: String) -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        lock.lock()
        guard let displaced = claimPrompt(context, connection: connection) else { lock.unlock(); return false }
        lock.unlock()
        displaced.forEach { $0.invalidate() }
        defer { release(context, connection: connection) }
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return false }
        let done = DispatchSemaphore(value: 0)
        let result = OSAllocatedUnfairLock(initialState: false)
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { accepted, _ in
            result.withLock { $0 = accepted }
            done.signal()
        }
        guard done.wait(timeout: .now() + 55) == .success else { return false }
        return result.withLock { $0 }
    }

    func readAuthorizedEnrollment(id: String, connection: UInt64, browser: Bool) -> Data? {
        guard !Task.isCancelled, let account = identity(id, browser: browser) else { return nil }
        let context = LAContext()
        context.localizedFallbackTitle = ""
        lock.lock()
        context.localizedReason = reason(connection: connection, email: account.email, server: account.server,
                                         releasesKey: true)
        guard let displaced = claimPrompt(context, connection: connection) else {
            lastFailure = String(localized: "Another Touch ID request is in progress.")
            lock.unlock()
            biometricLog.info("Touch ID read refused: another request is in progress (connection \(connection))")
            return nil
        }
        lastFailure = nil
        lock.unlock()
        displaced.forEach { $0.invalidate() }
        defer { release(context, connection: connection) }
        guard !Task.isCancelled else { return nil }
        let started = Date()
        let data: Data?
        do {
            data = try PlatformCredentials.read(PlatformCredentials.biometric, account.hash, context: context)
        } catch CredentialError.keychain(let status) {
            let reason = status == errSecUserCanceled ? "cancelled" : (SecCopyErrorMessageString(status, nil) as String? ?? "error")
            biometricLog.error("Touch ID read failed: OSStatus \(status) (\(reason, privacy: .public)), connection \(connection)")
            lock.lock()
            lastFailure = status == errSecUserCanceled ? nil
                : status == errSecAuthFailed
                ? String(localized: "Touch ID changed since enrollment. Turn Touch ID off and on again in Settings.")
                : String(localized: "Touch ID couldn’t read the key (\(reason)).")
            lock.unlock()
            return nil
        } catch {
            biometricLog.error("Touch ID read failed: \(error.localizedDescription, privacy: .public)")
            return nil
        }
        guard let data else {
            biometricLog.error("Touch ID read: no enrollment stored for this account")
            lock.lock(); lastFailure = String(localized: "Touch ID isn’t set up for this account."); lock.unlock()
            return nil
        }
        guard identity(id, browser: browser)?.hash == account.hash else {
            biometricLog.info("Touch ID read discarded: account changed during the prompt")
            return nil
        }
        biometricLog.info("Touch ID read succeeded in \(Date().timeIntervalSince(started), format: .fixed(precision: 1))s, connection \(connection)")
        return data
    }
}
