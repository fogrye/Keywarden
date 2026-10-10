import XCTest
@testable import Keywarden

/// The SDK scores locally, so these need no server or account.
@MainActor
final class PasswordStrengthTests: XCTestCase {
    func testSDKScoresWeakAndStrongPasswords() async throws {
        let client = SDKClient.shared
        let weak = try await client.passwordStrength(password: "password", email: "", inputs: [])
        let strong = try await client.passwordStrength(password: "VeryStrong123@#", email: "random@example.com", inputs: [])
        XCTAssertEqual(weak, 0)
        XCTAssertEqual(strong, 4)
    }

    func testItemNameAndUsernameArePenalized() async throws {
        let client = SDKClient.shared
        let plain = try await client.passwordStrength(password: "zebracorn7734", email: "", inputs: [])
        let penalized = try await client.passwordStrength(password: "zebracorn7734", email: "",
                                                          inputs: ["Zebracorn7734", "me"])
        XCTAssertLessThan(penalized, plain)
    }

    func testScoresMapToBitwardenBuckets() {
        XCTAssertEqual([0, 1, 2, 3, 4].map(PasswordStrengthMeter.label), ["Weak", "Weak", "Weak", "Good", "Strong"])
    }
}
