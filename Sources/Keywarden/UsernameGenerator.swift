import CryptoKit
import Foundation

/// Email forwarding services the SDK can create aliases with.
enum ForwarderService: String, Codable, CaseIterable, Identifiable {
    case simpleLogin, addy, firefoxRelay, fastmail, duckDuckGo, forwardEmail
    var id: Self { self }

    var title: String {
        switch self {
        case .simpleLogin: "SimpleLogin"
        case .addy: "addy.io"
        case .firefoxRelay: "Firefox Relay"
        case .fastmail: "Fastmail"
        case .duckDuckGo: "DuckDuckGo"
        case .forwardEmail: "ForwardEmail"
        }
    }

    /// Name the Rust side uses for the service.
    var backendName: String {
        switch self {
        case .simpleLogin: "simplelogin"
        case .addy: "addy"
        case .firefoxRelay: "firefox"
        case .fastmail: "fastmail"
        case .duckDuckGo: "duckduckgo"
        case .forwardEmail: "forwardemail"
        }
    }

    var secretTitle: String { self == .simpleLogin ? String(localized: "API key") : String(localized: "API token") }
    var needsBaseURL: Bool { self == .simpleLogin || self == .addy }
    var needsDomain: Bool { self == .addy || self == .forwardEmail }
}

/// Forwarder API keys and tokens live in the Keychain, one item per service, and never in UserDefaults.
enum ForwarderSecrets {
    static let keychainService = PlatformCredentials.forwarder

    /// The Keychain layer wants a 64-character hex account, so each service maps to a fixed digest.
    static func account(_ service: ForwarderService) -> String {
        SHA256.hash(data: Data("keywarden.forwarder.\(service.backendName)".utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func token(for service: ForwarderService) -> String? {
        guard let data = try? PlatformCredentials.read(keychainService, account(service)) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// An empty value removes the stored secret.
    @discardableResult
    static func setToken(_ token: String, for service: ForwarderService) -> Bool {
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            if trimmed.isEmpty { try PlatformCredentials.delete(keychainService, account(service)) }
            else { try PlatformCredentials.store(Data(trimmed.utf8), service: keychainService, account: account(service)) }
            return true
        } catch { return false }
    }
}

/// Username generator preferences. Only non-secret settings are here; tokens are in `ForwarderSecrets`.
struct UsernameOptions: Codable, Equatable {
    enum Kind: String, Codable, CaseIterable, Identifiable {
        case word = "Random word"
        case plusAddressed = "Plus addressed email"
        case catchAll = "Catch-all email"
        case forwarded = "Forwarded email alias"
        var id: Self { self }
        // The raw values are stored, so the shown titles are separate.
        var title: String {
            switch self {
            case .word: String(localized: "Random word")
            case .plusAddressed: String(localized: "Plus addressed email")
            case .catchAll: String(localized: "Catch-all email")
            case .forwarded: String(localized: "Forwarded email alias")
            }
        }
    }
    var kind = Kind.word
    var capitalize = false
    var includeNumber = false
    var email = ""
    var catchAllDomain = ""
    var service = ForwarderService.simpleLogin
    var simpleLoginURL = "https://app.simplelogin.io"
    var addyURL = "https://app.addy.io"
    var addyDomain = "anonaddy.me"
    var forwardEmailDomain = ""

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        func value<T: Decodable>(_ key: CodingKeys, _ fallback: T) -> T {
            (try? container.decodeIfPresent(T.self, forKey: key)) ?? fallback
        }
        kind = value(.kind, kind)
        capitalize = value(.capitalize, capitalize)
        includeNumber = value(.includeNumber, includeNumber)
        email = value(.email, email)
        catchAllDomain = value(.catchAllDomain, catchAllDomain)
        service = value(.service, service)
        simpleLoginURL = value(.simpleLoginURL, simpleLoginURL)
        addyURL = value(.addyURL, addyURL)
        addyDomain = value(.addyDomain, addyDomain)
        forwardEmailDomain = value(.forwardEmailDomain, forwardEmailDomain)
    }

    private static let key = "usernameGeneratorOptions"

    static var stored: UsernameOptions {
        guard let data = UserDefaults.standard.data(forKey: key),
              let options = try? JSONDecoder().decode(UsernameOptions.self, from: data) else { return UsernameOptions() }
        return options.clamped
    }

    func store() {
        if let data = try? JSONEncoder().encode(self) { UserDefaults.standard.set(data, forKey: Self.key) }
    }

    /// Trims stray whitespace and bounds lengths so a pasted blob cannot bloat the preferences.
    var clamped: UsernameOptions {
        var options = self
        func tidy(_ text: String) -> String { String(text.trimmingCharacters(in: .whitespacesAndNewlines).prefix(255)) }
        options.email = tidy(email)
        options.catchAllDomain = tidy(catchAllDomain)
        options.simpleLoginURL = tidy(simpleLoginURL)
        options.addyURL = tidy(addyURL)
        options.addyDomain = tidy(addyDomain)
        options.forwardEmailDomain = tidy(forwardEmailDomain)
        return options
    }

    /// Whether there is enough input to generate anything yet.
    var isReady: Bool {
        switch kind {
        case .word, .forwarded: true
        case .plusAddressed: !email.isEmpty
        case .catchAll: !catchAllDomain.isEmpty
        }
    }

    /// A forwarded alias makes a network call and creates an alias each time, so it only runs on request.
    var generatesAutomatically: Bool { kind != .forwarded }

    /// The request for the SDK. `token` is a secret: it is passed straight to the backend and not stored here.
    func request(token: String? = nil, website: String? = nil) -> [String: Any] {
        switch kind {
        case .word:
            return ["kind": "word", "capitalize": capitalize, "includeNumber": includeNumber]
        case .plusAddressed:
            return ["kind": "subaddress", "email": email]
        case .catchAll:
            return ["kind": "catchall", "domain": catchAllDomain]
        case .forwarded:
            var request: [String: Any] = ["kind": "forwarded", "service": service.backendName]
            if let token { request["token"] = token }
            if let website, !website.isEmpty { request["website"] = website }
            switch service {
            case .simpleLogin: request["baseUrl"] = simpleLoginURL
            case .addy: request["baseUrl"] = addyURL; request["domain"] = addyDomain
            case .forwardEmail: request["domain"] = forwardEmailDomain
            case .firefoxRelay, .fastmail, .duckDuckGo: break
            }
            return request
        }
    }
}
