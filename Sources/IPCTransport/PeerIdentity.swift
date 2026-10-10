import Darwin
import Foundation
import Security

/// Verify the audit identity supplied by the kernel, never a PID claimed in a frame.
enum PeerIdentity {
    static let appID = "xyz.kuvshynov.Keywarden"
    static let helperID = "xyz.kuvshynov.Keywarden.NativeHost"

    static func currentTeam() throws -> String {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCheckValidity(code, [], nil) == errSecSuccess else { throw TransportFailure.identity }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw TransportFailure.identity
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let team = (information as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String,
              !team.isEmpty else { throw TransportFailure.identity }
        return team
    }

    static func requirement(identifier: String, team: String) throws -> SecRequirement {
        guard identifier.range(of: #"^[A-Za-z0-9.-]+$"#, options: .regularExpression) != nil,
              team.range(of: #"^[A-Z0-9]+$"#, options: .regularExpression) != nil else {
            throw TransportFailure.identity
        }
        let text = "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(team)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else { throw TransportFailure.identity }
        return requirement
    }

    /// Returns the verified peer's pid.
    @discardableResult
    static func verifyPeer(_ fd: Int32, identifier: String, team: String) throws -> pid_t {
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) == 0,
              length == MemoryLayout<audit_token_t>.size,
              audit_token_to_euid(token) == geteuid() else { throw TransportFailure.identity }
        let audit = withUnsafeBytes(of: token) { Data($0) }
        var guest: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: audit] as CFDictionary,
                                             [], &guest) == errSecSuccess, let guest,
              SecCodeCheckValidity(guest, [], try requirement(identifier: identifier, team: team)) == errSecSuccess else {
            throw TransportFailure.identity
        }
        return audit_token_to_pid(token)
    }

    /// Checks the launching browser against `requirements` and returns the one it satisfies.
    static func verifyParent(_ pid: pid_t, requirements: [String]) throws -> String {
        let guest = try code(for: pid)
        for text in requirements {
            var requirement: SecRequirement?
            if SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
               let requirement, SecCodeCheckValidity(guest, [], requirement) == errSecSuccess {
                return text
            }
        }
        throw TransportFailure.identity
    }

    /// The signing identifier and team of a process, for diagnostics when a parent is refused.
    static func describe(_ pid: pid_t) -> String {
        guard let guest = try? code(for: pid) else { return "pid \(pid) (no code signature)" }
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation),
                                            &information) == errSecSuccess,
              let info = information as? [String: Any] else { return "pid \(pid) (unreadable signature)" }
        let identifier = info[kSecCodeInfoIdentifier as String] as? String ?? "?"
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String ?? "none"
        return "\(identifier), team \(team)"
    }

    private static func code(for pid: pid_t) throws -> SecCode {
        var guest: SecCode?
        guard pid > 1,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary,
                                             [], &guest) == errSecSuccess, let guest else {
            throw TransportFailure.identity
        }
        return guest
    }

    /// The Developer ID requirement pinned for a browser, derived from the installed app's
    /// signature. Nil for ad-hoc or unsigned apps, which cannot be told apart from impostors.
    static func browserPin(at app: URL) -> String? {
        var code: SecStaticCode?
        var information: CFDictionary?
        guard SecStaticCodeCreateWithPath(app as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation),
                                            &information) == errSecSuccess,
              let info = information as? [String: Any],
              let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
              team.range(of: #"^[A-Z0-9]{10}$"#, options: .regularExpression) != nil else { return nil }
        let pin = BrowserRegistry.teamRequirement(team)
        // Only Developer ID signatures chain to the certificate fields the requirement names.
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(pin as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess else { return nil }
        return pin
    }

    static func verifySignedHelper(at url: URL, team: String) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate),
                                         try requirement(identifier: helperID, team: team)) == errSecSuccess else {
            throw TransportFailure.identity
        }
    }
    static func verifySignedApp(at url: URL, team: String) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate),
                                         try requirement(identifier: appID, team: team)) == errSecSuccess else {
            throw TransportFailure.identity
        }
    }

}
