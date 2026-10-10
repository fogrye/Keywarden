import Foundation

/// Bitwarden Desktop's advanced search: a query that starts with `>`, such as
/// `>login.username:alice`, `>name:git*` or `>+folder:Work -type:card`.
///
/// Desktop uses a Lunr index; this is a small subset that runs over the decrypted list values:
///
/// - `field:value` limits a term to one field; `field:"two words"` takes a quoted value.
/// - `*` inside a term matches any run of characters. A term without `*` matches when the field
///   contains it; one with `*` matches a whole word (split at spaces and hyphens) or the whole value.
/// - `+term` must match, `-term` must not. Without any `+` term, at least one plain term must match.
///   A query of only `-` terms keeps everything else.
/// - Plain terms look at the name, subtitle, notes, username, websites, custom fields and
///   attachment names.
/// - Text with an unknown `field:` prefix (a URL, say) stays a plain term. A query that can't be
///   read (an unfinished quote, an empty value) makes the caller fall back to plain search.
///
/// Matching is case- and diacritic-insensitive. Passwords, hidden custom field values, card numbers
/// and codes are never searchable, because the list data never contains them.
struct AdvancedSearch: Equatable {
    struct Term: Equatable {
        enum Requirement { case optional, required, excluded }
        let requirement: Requirement
        /// The canonical field, or nil for a plain term.
        let field: Field?
        /// The lowercased, diacritic-folded text to look for.
        let pattern: String
        var hasWildcard: Bool { pattern.contains("*") }
    }

    /// A searchable field. `stored` ones are read from `VaultItemSummary.searchFields` by key.
    enum Field: Equatable {
        case name, subtitle, folder, type, favorite
        case stored(String)
        /// `fields.<name>`: a custom field's value, by the field's name.
        case customField(String)
    }

    let terms: [Term]

    /// The text after the leading `>`, or nil when `query` is not an advanced search.
    static func body(of query: String) -> String? {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix(">") else { return nil }
        return String(trimmed.dropFirst()).trimmingCharacters(in: .whitespaces)
    }

    /// Parses the text after `>`. Nil when it can't be read as a query.
    init?(parsing text: String) {
        var terms: [Term] = []
        var index = text.startIndex
        func skipSpaces() { while index < text.endIndex, text[index].isWhitespace { index = text.index(after: index) } }
        skipSpaces()
        while index < text.endIndex {
            var requirement = Term.Requirement.optional
            if text[index] == "+" || text[index] == "-" {
                requirement = text[index] == "+" ? .required : .excluded
                index = text.index(after: index)
            }
            // A word up to the next space, or up to a colon that follows a known field name.
            let wordStart = index
            var field: Field?
            var probe = index
            while probe < text.endIndex, !text[probe].isWhitespace, text[probe] != ":" { probe = text.index(after: probe) }
            if probe < text.endIndex, text[probe] == ":", let known = Self.field(named: String(text[wordStart..<probe])) {
                field = known
                index = text.index(after: probe)
            }
            var value = ""
            if index < text.endIndex, text[index] == "\"" {
                index = text.index(after: index)
                guard let close = text[index...].firstIndex(of: "\"") else { return nil }
                value = String(text[index..<close])
                index = text.index(after: close)
            } else {
                let valueStart = index
                while index < text.endIndex, !text[index].isWhitespace { index = text.index(after: index) }
                value = String(text[valueStart..<index])
            }
            // A lone "+" or "-", or "name:" with nothing after it, is not a term.
            guard !value.isEmpty else { return nil }
            terms.append(Term(requirement: requirement, field: field, pattern: Self.fold(value)))
            skipSpaces()
        }
        guard !terms.isEmpty else { return nil }
        self.terms = terms
    }

    // MARK: Matching

    func matches(_ item: VaultItemSummary, folderName: String?) -> Bool {
        var required = 0, requiredHits = 0, optional = 0, optionalHits = 0
        for term in terms {
            let hit = Self.matches(term, item, folderName)
            switch term.requirement {
            case .excluded: if hit { return false }
            case .required: required += 1; if hit { requiredHits += 1 }
            case .optional: optional += 1; if hit { optionalHits += 1 }
            }
        }
        if required > 0 { return requiredHits == required }
        return optional == 0 || optionalHits > 0
    }

    private static func matches(_ term: Term, _ item: VaultItemSummary, _ folderName: String?) -> Bool {
        let values: [String]
        if let field = term.field {
            values = self.values(of: field, item, folderName)
        } else {
            values = plainValues(item)
        }
        return values.contains { value(value: $0, matches: term) }
    }

    private static func value(value: String, matches term: Term) -> Bool {
        if !term.hasWildcard {
            return value.range(of: term.pattern, options: [.caseInsensitive, .diacriticInsensitive]) != nil
        }
        let folded = fold(value)
        if glob(term.pattern, folded) { return true }
        return folded.split(whereSeparator: { $0.isWhitespace || $0 == "-" }).contains { glob(term.pattern, String($0)) }
    }

    /// `*` matches any run of characters (including none); everything else matches itself.
    static func glob(_ pattern: String, _ text: String) -> Bool {
        let p = Array(pattern), t = Array(text)
        var pi = 0, ti = 0, star = -1, mark = 0
        while ti < t.count {
            if pi < p.count, p[pi] == "*" {
                star = pi
                mark = ti
                pi += 1
            } else if pi < p.count, p[pi] == t[ti] {
                pi += 1
                ti += 1
            } else if star >= 0 {
                pi = star + 1
                mark += 1
                ti = mark
            } else {
                return false
            }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }

    private static func plainValues(_ item: VaultItemSummary) -> [String] {
        var values = [item.name, item.subtitle] + item.searchValues
        for key in ["notes", "fields", "attachments.fileName"] { values += item.searchFields?[key] ?? [] }
        return values
    }

    private static func values(of field: Field, _ item: VaultItemSummary, _ folderName: String?) -> [String] {
        switch field {
        case .name: return [item.name]
        case .subtitle: return [item.subtitle]
        case .folder: return folderName.map { [$0] } ?? []
        case .favorite: return [item.favorite ? "true" : "false"]
        case .type: return typeNames(item.type)
        case .stored(let key): return item.searchFields?[key] ?? []
        case .customField(let name):
            let wanted = fold(name)
            return (item.searchFields ?? [:])
                .filter { $0.key.hasPrefix("fields.") && fold(String($0.key.dropFirst(7))) == wanted }
                .flatMap(\.value)
        }
    }

    /// The words `type:` understands for each item type.
    static func typeNames(_ type: Int) -> [String] {
        switch type {
        case 1: ["login"]
        case 2: ["note", "securenote"]
        case 3: ["card"]
        case 4: ["identity"]
        case 5: ["sshkey", "ssh"]
        case 6: ["bankaccount", "bank"]
        case 7: ["driverslicense", "license"]
        case 8: ["passport"]
        default: []
        }
    }

    // MARK: Fields

    private static let identityKeys = ["title", "firstName", "middleName", "lastName", "address1", "address2", "address3",
                                       "city", "state", "postalCode", "country", "company", "email", "phone", "username"]

    /// Field names as typed, lowercased, mapped to what they search.
    private static let fields: [String: Field] = {
        var map: [String: Field] = [
            "name": .name, "subtitle": .subtitle, "folder": .folder, "type": .type, "favorite": .favorite,
            "notes": .stored("notes"),
            "login.username": .stored("login.username"), "username": .stored("login.username"),
            "login.uris": .stored("login.uris"), "login.uri": .stored("login.uris"),
            "uris": .stored("login.uris"), "uri": .stored("login.uris"),
            "card.brand": .stored("card.brand"), "card.cardholdername": .stored("card.cardholderName"),
            "fields": .stored("fields"),
            "attachments": .stored("attachments.fileName"), "attachments.filename": .stored("attachments.fileName"),
        ]
        for key in identityKeys { map["identity.\(key.lowercased())"] = .stored("identity.\(key)") }
        return map
    }()

    private static func field(named name: String) -> Field? {
        let lowered = name.lowercased()
        if let field = fields[lowered] { return field }
        if lowered.hasPrefix("fields."), name.count > "fields.".count { return .customField(String(name.dropFirst("fields.".count))) }
        return nil
    }

    static func fold(_ text: String) -> String {
        text.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
    }
}
