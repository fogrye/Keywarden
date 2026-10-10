import Foundation

// These types mirror RustIpc/src/items.rs and vault.rs. Optional properties are omitted from the
// JSON when nil, which the Rust side reads as `None`.

struct VaultStatus: Decodable, Sendable {
    enum Phase: String, Decodable, Sendable { case loggedOut, locked, unlocked }
    let phase: Phase
    let email: String?
    let server: String?
    let accountHash: String?
    let accountId: String?
    let pinEnabled: Bool?
    let generation: UInt64
}

struct VaultFolder: Decodable, Identifiable, Hashable, Sendable {
    let id: String
    let name: String
}

struct VaultItemSummary: Decodable, Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let type: Int
    let favorite: Bool
    let folderId: String?
    let organizationId: String?
    let subtitle: String
    let searchValues: [String]
    let hasTotp: Bool
    let hasPasskey: Bool
    let deleted: Bool
    let archived: Bool
    let revisionDate: String
    let iconHost: String?
    /// Nonsecret text for advanced search (`>field:value`), by field. Absent in older snapshots.
    var searchFields: [String: [String]]? = nil

    var kind: VaultItemType { VaultItemType(rawValue: type) ?? .note }
}

struct VaultItemFailure: Decodable, Identifiable, Sendable {
    let id: String
    let message: String
}

struct VaultSnapshot: Decodable, Sendable {
    let email: String
    let server: String
    let accountId: String
    let accountHash: String
    let generation: UInt64
    let lastSync: UInt64?
    let items: [VaultItemSummary]
    let folders: [VaultFolder]
    let failures: [VaultItemFailure]
}

struct MutationResult: Decodable, Sendable {
    let snapshot: VaultSnapshot
    let id: String?
}

struct TotpCode: Decodable, Sendable {
    let code: String
    let period: Int
    let remaining: Int
}

struct VaultError: LocalizedError, Decodable, Sendable {
    let code: String
    let message: String
    var errorDescription: String? { message }
}

// MARK: - Items

enum VaultItemType: Int, CaseIterable, Identifiable, Sendable {
    case login = 1, note, card, identity, sshKey, bankAccount, driversLicense, passport

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .login: String(localized: "Login")
        case .note: String(localized: "Secure Note")
        case .card: String(localized: "Card")
        case .identity: String(localized: "Identity")
        case .sshKey: String(localized: "SSH Key")
        case .bankAccount: String(localized: "Bank Account")
        case .driversLicense: String(localized: "Driver’s License")
        case .passport: String(localized: "Passport")
        }
    }

    var pluralTitle: String {
        switch self {
        case .login: String(localized: "Logins")
        case .note: String(localized: "Secure Notes")
        case .card: String(localized: "Cards")
        case .identity: String(localized: "Identities")
        case .sshKey: String(localized: "SSH Keys")
        case .bankAccount: String(localized: "Bank Accounts")
        case .driversLicense: String(localized: "Driver’s Licenses")
        case .passport: String(localized: "Passports")
        }
    }

    /// "8 Logins", with the plural form the language needs.
    func counted(_ count: Int) -> String {
        switch self {
        case .login: String(localized: "\(count) Logins")
        case .note: String(localized: "\(count) Secure Notes")
        case .card: String(localized: "\(count) Cards")
        case .identity: String(localized: "\(count) Identities")
        case .sshKey: String(localized: "\(count) SSH Keys")
        case .bankAccount: String(localized: "\(count) Bank Accounts")
        case .driversLicense: String(localized: "\(count) Driver’s Licenses")
        case .passport: String(localized: "\(count) Passports")
        }
    }

    var symbol: String {
        switch self {
        case .login: "key.fill"
        case .note: "note.text"
        case .card: "creditcard.fill"
        case .identity: "person.text.rectangle.fill"
        case .sshKey: "terminal.fill"
        case .bankAccount: "building.columns.fill"
        case .driversLicense: "car.fill"
        case .passport: "globe"
        }
    }

    /// Types this client can create. SSH keys are view-only apart from name, notes and fields.
    static let creatable: [VaultItemType] = [.login, .note, .card, .identity, .bankAccount, .driversLicense, .passport]
}

struct ItemData: Codable, Equatable, Sendable {
    var id: String?
    var type: Int
    var name: String = ""
    var notes: String = ""
    var favorite = false
    var reprompt = false
    var folderId: String?
    var login: LoginData?
    var card: CardData?
    var identity: IdentityData?
    var sshKey: SshKeyData?
    var bankAccount: BankAccountData?
    var driversLicense: DriversLicenseData?
    var passport: PassportData?
    var fields: [FieldData] = []
    /// Asks the core to drop the login's passkeys on save. Omitted (nil) keeps them.
    var removePasskeys: Bool?

    var kind: VaultItemType { VaultItemType(rawValue: type) ?? .note }

    /// A copy for a new item, as Bitwarden's Clone does: no id, so saving takes the create path.
    /// Passkeys, attachments, password history, dates and the per-item key live outside `ItemData`
    /// and are never copied.
    func cloned() -> ItemData {
        var copy = self
        copy.id = nil
        copy.name += String(localized: " - Clone", comment: "Suffix added to the name of a cloned item")
        copy.removePasskeys = nil
        return copy
    }

    static func new(_ type: VaultItemType, folderId: String?) -> ItemData {
        var item = ItemData(type: type.rawValue, folderId: folderId)
        switch type {
        case .login: item.login = LoginData(uris: [UriData(uri: "")])
        case .card: item.card = CardData()
        case .identity: item.identity = IdentityData()
        case .bankAccount: item.bankAccount = BankAccountData()
        case .driversLicense: item.driversLicense = DriversLicenseData()
        case .passport: item.passport = PassportData()
        case .note, .sshKey: break
        }
        return item
    }
}

struct LoginData: Codable, Equatable, Sendable {
    var username = ""
    var password = ""
    var totp = ""
    var uris: [UriData] = []
}

struct UriData: Codable, Equatable, Identifiable, Sendable {
    var uri: String
    var match: Int?
    // Local identity for list editing; never encoded.
    var id = UUID()
    private enum CodingKeys: String, CodingKey { case uri, match }
}

/// How the browser extension decides a page matches a website (Bitwarden's UriMatchType).
/// `nil` in `UriData.match` means the account's default rule.
enum UriMatch: Int, CaseIterable, Identifiable, Sendable {
    case domain = 0, host, startsWith, exact, regularExpression, never
    var id: Self { self }
    var title: String {
        switch self {
        case .domain: String(localized: "Base domain")
        case .host: String(localized: "Host")
        case .startsWith: String(localized: "Starts with")
        case .exact: String(localized: "Exact")
        case .regularExpression: String(localized: "Regular expression")
        case .never: String(localized: "Never")
        }
    }
}

struct FieldData: Codable, Equatable, Identifiable, Sendable {
    enum Kind: Int, CaseIterable, Sendable {
        case text = 0, hidden, boolean, linked
        var title: String {
            switch self {
            case .text: String(localized: "Text")
            case .hidden: String(localized: "Hidden")
            case .boolean: String(localized: "Checkbox")
            case .linked: String(localized: "Linked")
            }
        }
    }
    var name = ""
    var value = ""
    var type = 0
    var linkedId: Int?
    var id = UUID()
    private enum CodingKeys: String, CodingKey { case name, value, type, linkedId }

    var kind: Kind { Kind(rawValue: type) ?? .text }
}

struct CardData: Codable, Equatable, Sendable {
    var cardholderName: String?
    var expMonth: String?
    var expYear: String?
    var code: String?
    var brand: String?
    var number: String?

    /// The brand Bitwarden stores for a card number ("Visa", "Amex", …), read from its leading
    /// digits; "Other" when none match, nil without a number.
    // ponytail: prefix table, not full IIN ranges; RuPay and Discover overlap only on rare BINs.
    static func brand(forNumber number: String) -> String? {
        let digits = number.filter(\.isNumber)
        guard !digits.isEmpty else { return nil }
        func starts(_ prefixes: [String]) -> Bool { prefixes.contains { digits.hasPrefix($0) } }
        func within(_ length: Int, _ range: ClosedRange<Int>) -> Bool {
            digits.count >= length && Int(digits.prefix(length)).map(range.contains) == true
        }
        if starts(["34", "37"]) { return "Amex" }
        if starts(["36", "38", "39"]) || within(3, 300...305) { return "Diners Club" }
        if starts(["35"]) { return "JCB" }
        if starts(["4"]) { return "Visa" }
        if starts(["5018", "5020", "5038", "5893", "6304", "6759", "6761", "6762", "6763"]) { return "Maestro" }
        if within(2, 51...55) || within(4, 2221...2720) { return "Mastercard" }
        if starts(["6011", "65"]) || within(3, 644...649) { return "Discover" }
        if starts(["62"]) { return "UnionPay" }
        if starts(["60", "81", "82", "508"]) { return "RuPay" }
        return "Other"
    }

    static func brandTitle(_ brand: String) -> String { brand == "Amex" ? "American Express" : brand }

    /// The number in the groups printed on the card: 4-6-5 for Amex, 4-6-4 for 14-digit Diners
    /// Club, fours otherwise. Anything but digits is left as typed.
    static func grouped(_ number: String) -> String {
        guard !number.isEmpty, number.allSatisfy(\.isNumber) else { return number }
        let brand = brand(forNumber: number)
        let sizes = brand == "Amex" ? [4, 6, 5] : brand == "Diners Club" && number.count == 14 ? [4, 6, 4] : []
        var groups: [Substring] = []
        var rest = Substring(number)
        for size in sizes + Array(repeating: 4, count: rest.count) where !rest.isEmpty {
            groups.append(rest.prefix(size))
            rest = rest.dropFirst(size)
        }
        return groups.joined(separator: " ")
    }

    /// The grouped number with every digit but the last four hidden: "•••• •••• •••• 4444".
    static func masked(_ number: String) -> String {
        var visible = 4
        return String(grouped(number).reversed().map { char -> Character in
            guard char.isNumber else { return char }
            visible -= 1
            return visible >= 0 ? char : "•"
        }.reversed())
    }

    /// "04/2031", or whichever half is stored.
    var expiration: String? {
        let month = expMonth.flatMap { Int($0) }.map { String(format: "%02d", $0) } ?? expMonth
        let parts = [month, expYear].compactMap { $0 }.filter { !$0.isEmpty }
        return parts.isEmpty ? nil : parts.joined(separator: "/")
    }
}

struct IdentityData: Codable, Equatable, Sendable {
    var title: String?
    var firstName: String?
    var middleName: String?
    var lastName: String?
    var address1: String?
    var address2: String?
    var address3: String?
    var city: String?
    var state: String?
    var postalCode: String?
    var country: String?
    var company: String?
    var email: String?
    var phone: String?
    var ssn: String?
    var username: String?
    var passportNumber: String?
    var licenseNumber: String?
}

struct SshKeyData: Codable, Equatable, Sendable {
    var privateKey: String
    var publicKey: String
    var fingerprint: String
}

struct BankAccountData: Codable, Equatable, Sendable {
    var bankName: String?
    var nameOnAccount: String?
    var accountType: String?
    var accountNumber: String?
    var routingNumber: String?
    var branchNumber: String?
    var pin: String?
    var swiftCode: String?
    var iban: String?
    var bankContactPhone: String?
}

struct DriversLicenseData: Codable, Equatable, Sendable {
    var firstName: String?
    var middleName: String?
    var lastName: String?
    var dateOfBirth: String?
    var licenseNumber: String?
    var issuingCountry: String?
    var issuingState: String?
    var issueDate: String?
    var expirationDate: String?
    var issuingAuthority: String?
    var licenseClass: String?
}

struct PassportData: Codable, Equatable, Sendable {
    var surname: String?
    var givenName: String?
    var dateOfBirth: String?
    var sex: String?
    var birthPlace: String?
    var nationality: String?
    var issuingCountry: String?
    var passportNumber: String?
    var passportType: String?
    var nationalIdentificationNumber: String?
    var issuingAuthority: String?
    var issueDate: String?
    var expirationDate: String?
}

struct ItemDetail: Decodable, Sendable {
    struct Passkey: Decodable, Equatable, Sendable {
        let rpId: String
        let userName: String?
        let creationDate: String
    }
    struct HistoryEntry: Decodable, Sendable {
        let password: String
        let lastUsedDate: String
    }
    struct Attachment: Decodable, Identifiable, Equatable, Sendable {
        let id: String
        let fileName: String
        let size: String?
    }
    let item: ItemData
    let organizationId: String?
    let editable: Bool
    let viewPassword: Bool
    let passkeys: [Passkey]
    let passwordHistory: [HistoryEntry]
    let attachments: [Attachment]
    let creationDate: String
    let revisionDate: String
    let deletedDate: String?
    let archivedDate: String?
    let passwordRevisionDate: String?

    var id: String { item.id ?? "" }

    /// The website Open Website launches: the first http(s) one.
    var launchURL: URL? { item.login?.uris.lazy.compactMap { UriData.launchURL($0.uri) }.first }

    /// What the keyboard can copy, in the order the detail shows it: Item › Copy lists these, and
    /// the detail's rows take focus under the same ids. Values hidden by a "hide passwords" share
    /// are left out; SSH keys are out of scope.
    var copyableFields: [CopyableField] {
        var fields: [CopyableField] = []
        if item.kind == .login, let login = item.login {
            if !login.username.isEmpty {
                fields.append(.init(id: CopyableField.username, label: String(localized: "Username"), value: login.username))
            }
            if !login.password.isEmpty, viewPassword {
                fields.append(.init(id: CopyableField.password, label: String(localized: "Password"),
                                    value: login.password, kind: .secret))
            }
            if !login.totp.isEmpty {
                fields.append(.init(id: CopyableField.totp, label: String(localized: "One-time code"),
                                    value: login.totp, kind: .totp))
            }
            for (index, uri) in login.uris.enumerated() where !uri.uri.isEmpty {
                let label = UriData.launchURL(uri.uri)?.host() ?? uri.uri
                fields.append(.init(id: CopyableField.websiteID(index), label: label, value: uri.uri, kind: .website))
            }
        }
        switch item.kind {
        case .card: fields += (item.card ?? CardData()).fields
        case .identity: fields += CopyableField.spec(item.identity, IdentityData.specs)
        case .bankAccount: fields += CopyableField.spec(item.bankAccount, BankAccountData.specs)
        case .driversLicense: fields += CopyableField.spec(item.driversLicense, DriversLicenseData.specs)
        case .passport: fields += CopyableField.spec(item.passport, PassportData.specs)
        case .login, .note, .sshKey: break
        }
        if !item.notes.isEmpty {
            fields.append(.init(id: CopyableField.notes, label: String(localized: "Notes"), value: item.notes))
        }
        for (index, field) in item.fields.enumerated() where !field.value.isEmpty {
            let label = field.name.isEmpty ? String(localized: "Field") : field.name
            switch field.kind {
            case .text: fields.append(.init(id: CopyableField.customID(index), label: label, value: field.value))
            case .hidden where viewPassword:
                fields.append(.init(id: CopyableField.customID(index), label: label, value: field.value, kind: .secret))
            default: break
            }
        }
        return fields
    }
}

/// A value of the shown item the keyboard can copy (see `ItemDetail.copyableFields`).
struct CopyableField: Identifiable, Equatable, Sendable {
    enum Kind: Sendable { case text, secret, totp, website }

    static let username = "login.username"
    static let password = "login.password"
    static let totp = "login.totp"
    static let notes = "notes"
    static func websiteID(_ index: Int) -> String { "uri.\(index)" }
    static func customID(_ index: Int) -> String { "field.\(index)" }
    static func specID(_ index: Int) -> String { "spec.\(index)" }

    let id: String
    let label: String
    /// What is copied. For a one-time code this is the key; the current code is copied instead.
    let value: String
    var kind: Kind = .text
    /// What a secret shows while hidden, and the value's revealed form, when not dots and the value.
    var mask: String?
    var display: String?

    static func spec<Root>(_ data: Root?, _ specs: [FieldSpec<Root>]) -> [CopyableField] {
        guard let data else { return [] }
        return specs.enumerated().compactMap { index, field in
            guard let value = data[keyPath: field.path], !value.isEmpty else { return nil }
            return CopyableField(id: specID(index), label: field.label, value: value, kind: field.secret ? .secret : .text)
        }
    }
}

extension UriData {
    /// The address a website opens at: http(s) only, with https assumed when no scheme is given.
    static func launchURL(_ uri: String) -> URL? {
        let candidate = uri.contains("://") ? uri : "https://\(uri)"
        guard let url = URL(string: candidate), ["http", "https"].contains(url.scheme?.lowercased()) else { return nil }
        return url
    }
}

extension CardData {
    /// The detail's rows, in the editor's order: name, number, the detected brand, expiry as one
    /// row, code. Empty values are left out.
    var fields: [CopyableField] {
        let number = number ?? "", code = code ?? ""
        let rows: [CopyableField] = [
            .init(id: "card.name", label: String(localized: "Cardholder name"), value: cardholderName ?? ""),
            .init(id: "card.number", label: String(localized: "Number"), value: number, kind: .secret,
                  mask: Self.masked(number), display: Self.grouped(number)),
            .init(id: "card.brand", label: String(localized: "Brand"), value: brand.map(Self.brandTitle) ?? ""),
            .init(id: "card.expiration", label: String(localized: "Expiration date"), value: expiration ?? ""),
            .init(id: "card.code", label: String(localized: "Security code"), value: code, kind: .secret,
                  mask: String(repeating: "•", count: code.count)),
        ]
        return rows.filter { !$0.value.isEmpty }
    }
}

// MARK: - Field layouts

/// One labelled text property of a structured item type, used both to display and to edit it.
// Key paths into value types are immutable; the specs are static tables.
struct FieldSpec<Root>: Identifiable, @unchecked Sendable {
    let label: String
    let path: WritableKeyPath<Root, String?>
    var secret = false
    var monospaced = false
    // Not the label: translated labels can coincide.
    var id: WritableKeyPath<Root, String?> { path }
}

extension IdentityData {
    static let specs: [FieldSpec<IdentityData>] = [
        .init(label: String(localized: "Title"), path: \.title),
        .init(label: String(localized: "First name"), path: \.firstName),
        .init(label: String(localized: "Middle name"), path: \.middleName),
        .init(label: String(localized: "Last name"), path: \.lastName),
        .init(label: String(localized: "Username"), path: \.username),
        .init(label: String(localized: "Company"), path: \.company),
        .init(label: String(localized: "Email"), path: \.email),
        .init(label: String(localized: "Phone"), path: \.phone),
        .init(label: String(localized: "Social Security number"), path: \.ssn, secret: true),
        .init(label: String(localized: "Passport number"), path: \.passportNumber, secret: true),
        .init(label: String(localized: "License number"), path: \.licenseNumber, secret: true),
        .init(label: String(localized: "Address 1"), path: \.address1),
        .init(label: String(localized: "Address 2"), path: \.address2),
        .init(label: String(localized: "Address 3"), path: \.address3),
        .init(label: String(localized: "City"), path: \.city),
        .init(label: String(localized: "State / Province"), path: \.state),
        .init(label: String(localized: "Postal code"), path: \.postalCode),
        .init(label: String(localized: "Country"), path: \.country),
    ]
}

extension BankAccountData {
    static let specs: [FieldSpec<BankAccountData>] = [
        .init(label: String(localized: "Bank name"), path: \.bankName),
        .init(label: String(localized: "Name on account"), path: \.nameOnAccount),
        .init(label: String(localized: "Account type"), path: \.accountType),
        .init(label: String(localized: "Account number"), path: \.accountNumber, secret: true, monospaced: true),
        .init(label: String(localized: "Routing number"), path: \.routingNumber, monospaced: true),
        .init(label: String(localized: "Branch number"), path: \.branchNumber, monospaced: true),
        .init(label: String(localized: "PIN"), path: \.pin, secret: true, monospaced: true),
        .init(label: String(localized: "SWIFT code"), path: \.swiftCode, monospaced: true),
        .init(label: String(localized: "IBAN"), path: \.iban, secret: true, monospaced: true),
        .init(label: String(localized: "Bank phone"), path: \.bankContactPhone),
    ]
}

extension DriversLicenseData {
    static let specs: [FieldSpec<DriversLicenseData>] = [
        .init(label: String(localized: "First name"), path: \.firstName),
        .init(label: String(localized: "Middle name"), path: \.middleName),
        .init(label: String(localized: "Last name"), path: \.lastName),
        .init(label: String(localized: "Date of birth"), path: \.dateOfBirth),
        .init(label: String(localized: "License number"), path: \.licenseNumber, secret: true, monospaced: true),
        .init(label: String(localized: "Class"), path: \.licenseClass),
        .init(label: String(localized: "Issuing country"), path: \.issuingCountry),
        .init(label: String(localized: "Issuing state"), path: \.issuingState),
        .init(label: String(localized: "Issuing authority"), path: \.issuingAuthority),
        .init(label: String(localized: "Issue date"), path: \.issueDate),
        .init(label: String(localized: "Expiration date"), path: \.expirationDate),
    ]
}

extension PassportData {
    static let specs: [FieldSpec<PassportData>] = [
        .init(label: String(localized: "Given name"), path: \.givenName),
        .init(label: String(localized: "Surname"), path: \.surname),
        .init(label: String(localized: "Date of birth"), path: \.dateOfBirth),
        .init(label: String(localized: "Sex"), path: \.sex),
        .init(label: String(localized: "Place of birth"), path: \.birthPlace),
        .init(label: String(localized: "Nationality"), path: \.nationality),
        .init(label: String(localized: "Passport number"), path: \.passportNumber, secret: true, monospaced: true),
        .init(label: String(localized: "Passport type"), path: \.passportType),
        .init(label: String(localized: "National ID number"), path: \.nationalIdentificationNumber, secret: true),
        .init(label: String(localized: "Issuing country"), path: \.issuingCountry),
        .init(label: String(localized: "Issuing authority"), path: \.issuingAuthority),
        .init(label: String(localized: "Issue date"), path: \.issueDate),
        .init(label: String(localized: "Expiration date"), path: \.expirationDate),
    ]
}

/// Bitwarden's linked-field ids (`LinkedIdType`) for the types that support them.
enum LinkedTarget {
    static let names: [Int: String] = [
        100: String(localized: "Username"),
        101: String(localized: "Password"),
        300: String(localized: "Cardholder name"),
        301: String(localized: "Expiration month"),
        302: String(localized: "Expiration year"),
        303: String(localized: "Security code"),
        304: String(localized: "Brand"),
        305: String(localized: "Number"),
        400: String(localized: "Title"),
        401: String(localized: "Middle name"),
        402: String(localized: "Address 1"),
        403: String(localized: "Address 2"),
        404: String(localized: "Address 3"),
        405: String(localized: "City"),
        406: String(localized: "State"),
        407: String(localized: "Postal code"),
        408: String(localized: "Country"),
        409: String(localized: "Company"),
        410: String(localized: "Email"),
        411: String(localized: "Phone"),
        412: String(localized: "SSN"),
        413: String(localized: "Username"),
        414: String(localized: "Passport number"),
        415: String(localized: "License number"),
        416: String(localized: "First name"),
        417: String(localized: "Last name"),
        418: String(localized: "Full name"),
    ]
}

enum VaultDate {
    // ISO8601DateFormatter is thread-safe once configured.
    nonisolated(unsafe) private static let parser: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
    nonisolated(unsafe) private static let fallback = ISO8601DateFormatter()

    static func parse(_ text: String?) -> Date? {
        guard let text else { return nil }
        return parser.date(from: text) ?? fallback.date(from: text)
    }

    static func display(_ text: String?) -> String? {
        parse(text)?.formatted(date: .abbreviated, time: .shortened)
    }
}
