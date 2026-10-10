import Foundation
import XCTest
@testable import Keywarden

@MainActor
final class UsernameGeneratorTests: XCTestCase {
    private let defaultsKey = "usernameGeneratorOptions"
    private var savedDefaults: Data?

    override func setUp() async throws {
        savedDefaults = UserDefaults.standard.data(forKey: defaultsKey)
        UserDefaults.standard.removeObject(forKey: defaultsKey)
    }

    override func tearDown() async throws {
        if let savedDefaults { UserDefaults.standard.set(savedDefaults, forKey: defaultsKey) }
        else { UserDefaults.standard.removeObject(forKey: defaultsKey) }
    }

    /// Debug builds keep credentials in memory only under a UUID `BW_TEST_NAMESPACE`; never touch the real Keychain.
    private func requireIsolatedCredentials() throws {
        let namespace = ProcessInfo.processInfo.environment["BW_TEST_NAMESPACE"]
        try XCTSkipIf(namespace.flatMap(UUID.init) == nil, "Needs an isolated BW_TEST_NAMESPACE (a UUID)")
    }

    // MARK: Options

    func testRequestsMatchEachUsernameType() {
        var options = UsernameOptions()
        options.capitalize = true
        options.includeNumber = true
        XCTAssertEqual(options.request()["kind"] as? String, "word")
        XCTAssertEqual(options.request()["capitalize"] as? Bool, true)
        XCTAssertEqual(options.request()["includeNumber"] as? Bool, true)

        options.kind = .plusAddressed
        options.email = "you@example.com"
        XCTAssertEqual(options.request()["kind"] as? String, "subaddress")
        XCTAssertEqual(options.request()["email"] as? String, "you@example.com")

        options.kind = .catchAll
        options.catchAllDomain = "example.org"
        XCTAssertEqual(options.request()["kind"] as? String, "catchall")
        XCTAssertEqual(options.request()["domain"] as? String, "example.org")
    }

    func testForwardedRequestsCarryOnlyTheFieldsEachServiceNeeds() {
        var options = UsernameOptions()
        options.kind = .forwarded
        options.addyDomain = "anonaddy.me"
        options.forwardEmailDomain = "mail.example.com"
        for service in ForwarderService.allCases {
            options.service = service
            let request = options.request(token: "t", website: "https://shop.example.com")
            XCTAssertEqual(request["kind"] as? String, "forwarded")
            XCTAssertEqual(request["service"] as? String, service.backendName)
            XCTAssertEqual(request["token"] as? String, "t")
            XCTAssertEqual(request["website"] as? String, "https://shop.example.com")
            XCTAssertEqual(request["baseUrl"] != nil, service.needsBaseURL, "\(service)")
            XCTAssertEqual(request["domain"] != nil, service.needsDomain, "\(service)")
        }
        XCTAssertNil(options.request(token: nil, website: "")["website"])
        XCTAssertEqual(Set(ForwarderService.allCases.map(\.backendName)).count, 6)
    }

    func testForwardedAliasesAreNeverCreatedAutomatically() {
        var options = UsernameOptions()
        XCTAssertTrue(options.generatesAutomatically)
        options.kind = .forwarded
        XCTAssertFalse(options.generatesAutomatically)
        options.kind = .plusAddressed
        XCTAssertFalse(options.isReady)
        options.email = "you@example.com"
        XCTAssertTrue(options.isReady)
        options.kind = .catchAll
        XCTAssertFalse(options.isReady)
    }

    func testStoredOptionsTrimAndTolerateMissingKeys() throws {
        var options = UsernameOptions()
        options.email = "  you@example.com \n"
        options.catchAllDomain = String(repeating: "a", count: 400)
        XCTAssertEqual(options.clamped.email, "you@example.com")
        XCTAssertEqual(options.clamped.catchAllDomain.count, 255)
        let partial = try JSONDecoder().decode(UsernameOptions.self, from: Data(#"{"kind":"Catch-all email","email":"a@b.co"}"#.utf8))
        XCTAssertEqual(partial.kind, .catchAll)
        XCTAssertEqual(partial.email, "a@b.co")
        XCTAssertEqual(partial.service, .simpleLogin)
        let broken = try JSONDecoder().decode(UsernameOptions.self, from: Data(#"{"kind":"nonsense","service":7}"#.utf8))
        XCTAssertEqual(broken, UsernameOptions())
    }

    func testTypeSelectionDoesNotChangeThePasswordButton() throws {
        var options = GeneratorOptions()
        options.mode = .passphrase
        options.usernameSelected = true
        let round = try JSONDecoder().decode(GeneratorOptions.self, from: JSONEncoder().encode(options))
        XCTAssertTrue(round.usernameSelected)
        XCTAssertEqual(round.request["mode"] as? String, "passphrase")
    }

    // MARK: Secrets

    func testForwarderTokensGoToTheKeychainAndNeverToUserDefaults() throws {
        try requireIsolatedCredentials()
        let secret = "tok-\(UUID().uuidString)"
        var options = UsernameOptions()
        options.kind = .forwarded
        options.service = .fastmail
        options.store()
        XCTAssertTrue(ForwarderSecrets.setToken(secret, for: .fastmail))
        defer { ForwarderSecrets.setToken("", for: .fastmail) }

        XCTAssertEqual(ForwarderSecrets.token(for: .fastmail), secret)
        let stored = try XCTUnwrap(PlatformCredentials.read(PlatformCredentials.forwarder, ForwarderSecrets.account(.fastmail)))
        XCTAssertEqual(String(decoding: stored, as: UTF8.self), secret)

        // The token is nowhere in the preferences: not in the options blob, not in any other key.
        let defaults = UserDefaults.standard.dictionaryRepresentation()
        XCTAssertFalse(String(describing: defaults).contains(secret))
        let blob = try XCTUnwrap(UserDefaults.standard.data(forKey: defaultsKey))
        XCTAssertFalse(String(decoding: blob, as: UTF8.self).lowercased().contains("token"))
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(options), as: UTF8.self).contains(secret))

        // Other services do not see it, and clearing the field removes it.
        XCTAssertNil(ForwarderSecrets.token(for: .duckDuckGo))
        ForwarderSecrets.setToken("  ", for: .fastmail)
        XCTAssertNil(ForwarderSecrets.token(for: .fastmail))
    }

    func testEachServiceHasItsOwnKeychainAccount() {
        let accounts = ForwarderService.allCases.map(ForwarderSecrets.account)
        XCTAssertEqual(Set(accounts).count, accounts.count)
        for account in accounts {
            XCTAssertEqual(account.count, 64)
            XCTAssertTrue(account.allSatisfy { $0.isHexDigit && !$0.isUppercase })
        }
    }

    // MARK: SDK (no network)

    func testLocalUsernameTypesGenerateThroughTheSDK() async throws {
        var options = UsernameOptions()
        options.capitalize = true
        options.includeNumber = true
        let word = try await SDKClient.shared.generateUsername(options: options.request())
        XCTAssertTrue(word.first?.isUppercase == true)
        XCTAssertTrue(word.suffix(4).allSatisfy(\.isNumber), word)

        options.kind = .plusAddressed
        options.email = "you@example.com"
        let plus = try await SDKClient.shared.generateUsername(options: options.request())
        XCTAssertTrue(plus.hasPrefix("you+") && plus.hasSuffix("@example.com"), plus)

        options.kind = .catchAll
        options.catchAllDomain = "example.org"
        let catchAll = try await SDKClient.shared.generateUsername(options: options.request())
        XCTAssertTrue(catchAll.hasSuffix("@example.org"), catchAll)
    }

    func testBadUsernameInputsAndForwarderSetupSurfaceErrorsWithoutNetwork() async throws {
        var options = UsernameOptions()
        options.kind = .plusAddressed
        options.email = "not an email"
        await assertFails(options.request(), "Enter a valid email address.")

        options.kind = .forwarded
        options.service = .firefoxRelay
        await assertFails(options.request(token: nil), "Enter the API key or token.")

        // A token is never sent over plain HTTP to a remote server; this fails before any request.
        options.service = .simpleLogin
        options.simpleLoginURL = "http://sl.example.com"
        await assertFails(options.request(token: "secret"), "The base URL must be an https:// address.")
    }

    private func assertFails(_ request: [String: Any], _ message: String, line: UInt = #line) async {
        do {
            let value = try await SDKClient.shared.generateUsername(options: request)
            XCTFail("Expected an error, got a value of \(value.count) characters", line: line)
        } catch {
            XCTAssertEqual((error as? VaultError)?.message, message, line: line)
        }
    }
}
