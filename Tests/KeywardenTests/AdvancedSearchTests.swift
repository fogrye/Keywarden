import Foundation
import XCTest
@testable import Keywarden

/// The `>` search: parsing, field scoping, wildcards, +/- and the fallback to plain search.
@MainActor
final class AdvancedSearchTests: XCTestCase {
    private func item(_ name: String, type: Int = 1, favorite: Bool = false, folder: String? = nil, subtitle: String = "",
                      searchValues: [String] = [], fields: [String: [String]] = [:]) -> VaultItemSummary {
        VaultItemSummary(id: UUID().uuidString, name: name, type: type, favorite: favorite, folderId: folder,
                         organizationId: nil, subtitle: subtitle, searchValues: searchValues, hasTotp: false,
                         hasPasskey: false, deleted: false, archived: false, revisionDate: "2026-01-01T00:00:00Z",
                         iconHost: nil, searchFields: fields)
    }

    /// The names of the items a query keeps.
    private func names(_ query: String, in items: [VaultItemSummary], folders: [String: String] = [:]) -> [String] {
        guard let search = AdvancedSearch(parsing: query) else { return ["<unreadable>"] }
        return items.filter { search.matches($0, folderName: $0.folderId.flatMap { folders[$0] }) }.map(\.name)
    }

    private var vault: [VaultItemSummary] {
        [
            item("GitHub", subtitle: "alice", searchValues: ["alice", "https://github.com"],
                 fields: ["login.username": ["alice"], "login.uris": ["https://github.com"], "notes": ["work account"],
                          "fields": ["Region", "EU"], "fields.Region": ["EU"]]),
            item("My git repo", subtitle: "bob", searchValues: ["bob", "https://git.example.org"],
                 fields: ["login.username": ["bob"], "login.uris": ["https://git.example.org"]]),
            item("Digital ID", type: 4, subtitle: "Alex Example",
                 fields: ["identity.firstName": ["Alex"], "identity.lastName": ["Example"], "identity.city": ["Café Town"]]),
            item("Alice Visa", type: 3, favorite: true, folder: "f-work", subtitle: "Visa *1111",
                 fields: ["card.brand": ["Visa"], "card.cardholderName": ["Alice Person"]]),
            item("Wi-Fi", type: 2, folder: "f-home", subtitle: "Network", fields: ["notes": ["password is on the router"]]),
        ]
    }
    private let folders = ["f-work": "Work", "f-home": "Home"]

    // MARK: Parsing

    func testEmptyOrUnfinishedQueriesDoNotParse() {
        for text in ["", "   ", "+", "-", "name:", "name:\"unfinished", "+name:", "\"\"", "- x"] {
            XCTAssertNil(AdvancedSearch(parsing: text), "'\(text)'")
        }
        XCTAssertNotNil(AdvancedSearch(parsing: "  name:git*  "))
    }

    func testOnlyQueriesStartingWithAGreaterThanSignAreAdvanced() {
        XCTAssertEqual(AdvancedSearch.body(of: ">name:git*"), "name:git*")
        XCTAssertEqual(AdvancedSearch.body(of: "  > +folder:Work "), "+folder:Work")
        XCTAssertNil(AdvancedSearch.body(of: "git"))
        XCTAssertNil(AdvancedSearch.body(of: "a>b"))
        XCTAssertEqual(AdvancedSearch.body(of: ">"), "")
    }

    func testUnknownFieldPrefixesStayPlainTerms() throws {
        let url = try XCTUnwrap(AdvancedSearch(parsing: "https://github.com"))
        XCTAssertEqual(url.terms.count, 1)
        XCTAssertNil(url.terms[0].field)
        XCTAssertEqual(url.terms[0].pattern, "https://github.com")
        let typo = try XCTUnwrap(AdvancedSearch(parsing: "nmae:git"))
        XCTAssertNil(typo.terms[0].field)
        XCTAssertEqual(names("https://github.com", in: vault), ["GitHub"], "a URL matches as text")
    }

    func testTermsCarryRequirementsFieldsAndQuotedValues() throws {
        let search = try XCTUnwrap(AdvancedSearch(parsing: "+folder:Work -type:card name:\"my git\" plain"))
        XCTAssertEqual(search.terms.map(\.requirement), [.required, .excluded, .optional, .optional])
        XCTAssertEqual(search.terms.map(\.field), [.folder, .type, .name, nil])
        XCTAssertEqual(search.terms[2].pattern, "my git")
    }

    // MARK: Field scoping

    func testFieldScopeLimitsWhereATermIsLookedFor() {
        // "alice" is a username, a name and a cardholder: each field finds only its own.
        XCTAssertEqual(names("login.username:alice", in: vault), ["GitHub"])
        XCTAssertEqual(names("username:alice", in: vault), ["GitHub"], "alias")
        XCTAssertEqual(names("name:alice", in: vault), ["Alice Visa"])
        XCTAssertEqual(names("card.cardholdername:alice", in: vault), ["Alice Visa"])
        XCTAssertEqual(Set(names("alice", in: vault)), ["GitHub", "Alice Visa"], "plain looks everywhere")
        XCTAssertEqual(names("login.uris:example.org", in: vault), ["My git repo"])
        XCTAssertEqual(names("uri:github", in: vault), ["GitHub"], "alias")
        XCTAssertEqual(names("notes:router", in: vault), ["Wi-Fi"])
        XCTAssertEqual(names("card.brand:visa", in: vault), ["Alice Visa"])
        XCTAssertEqual(names("identity.firstname:alex", in: vault), ["Digital ID"])
        XCTAssertEqual(names("identity.city:cafe", in: vault), ["Digital ID"], "diacritics are ignored")
        XCTAssertEqual(names("subtitle:network", in: vault), ["Wi-Fi"])
    }

    func testCustomFieldsAreScopedByTheirName() {
        XCTAssertEqual(names("fields.Region:EU", in: vault), ["GitHub"])
        XCTAssertEqual(names("fields.region:eu", in: vault), ["GitHub"], "field names ignore case")
        XCTAssertEqual(names("fields.Other:EU", in: vault), [])
        XCTAssertEqual(names("fields:region", in: vault), ["GitHub"], "any field name or value")
    }

    func testFolderTypeAndFavoriteFields() {
        XCTAssertEqual(names("folder:work", in: vault, folders: folders), ["Alice Visa"])
        XCTAssertEqual(names("type:card", in: vault), ["Alice Visa"])
        XCTAssertEqual(names("type:login", in: vault), ["GitHub", "My git repo"])
        XCTAssertEqual(names("type:securenote", in: vault), ["Wi-Fi"])
        XCTAssertEqual(names("type:note", in: vault), ["Wi-Fi"])
        XCTAssertEqual(names("favorite:true", in: vault), ["Alice Visa"])
    }

    func testNothingSecretIsSearchable() {
        // The list data has no passwords or card numbers, so their text finds nothing; "password"
        // matches the note that mentions the word, not any login's password.
        XCTAssertEqual(names("4111111111111111", in: vault), [])
        XCTAssertEqual(names("login.password:hunter2", in: vault), [], "there is no password field to search")
        XCTAssertEqual(names("card.number:4111", in: vault), [], "an unknown field is a plain term")
    }

    // MARK: Wildcards

    func testWildcardsMatchWholeWordsOrValues() {
        XCTAssertEqual(names("name:git*", in: vault), ["GitHub", "My git repo"], "a word starting with git")
        XCTAssertFalse(names("name:git*", in: vault).contains("Digital ID"))
        XCTAssertEqual(names("name:*hub", in: vault), ["GitHub"])
        XCTAssertEqual(names("name:g*b", in: vault), ["GitHub"])
        XCTAssertEqual(names("name:*it*", in: vault), ["GitHub", "My git repo", "Digital ID"])
        XCTAssertEqual(names("name:git", in: vault), ["GitHub", "My git repo", "Digital ID"], "no wildcard: contains")
        XCTAssertEqual(names("login.uris:https://git*", in: vault), ["GitHub", "My git repo"], "whole value")
        XCTAssertEqual(names("name:wi-fi", in: vault), ["Wi-Fi"])
        XCTAssertEqual(names("name:fi*", in: vault), ["Wi-Fi"], "words split at hyphens")
    }

    func testGlobMatching() {
        XCTAssertTrue(AdvancedSearch.glob("*", ""))
        XCTAssertTrue(AdvancedSearch.glob("a*", "a"))
        XCTAssertTrue(AdvancedSearch.glob("a*b*c", "aXXbYYc"))
        XCTAssertTrue(AdvancedSearch.glob("a*b*c", "abc"))
        XCTAssertFalse(AdvancedSearch.glob("a*b*c", "aXXbYY"))
        XCTAssertFalse(AdvancedSearch.glob("abc", "abcd"))
        XCTAssertTrue(AdvancedSearch.glob("**x", "x"))
        XCTAssertFalse(AdvancedSearch.glob("a", ""))
        XCTAssertTrue(AdvancedSearch.glob("é*", "école"), "compares characters, not bytes")
    }

    // MARK: Required and excluded terms

    func testRequiredAndExcludedTerms() {
        XCTAssertEqual(names("+folder:Work -type:card", in: vault, folders: folders), [])
        XCTAssertEqual(names("+folder:Work -type:login", in: vault, folders: folders), ["Alice Visa"])
        XCTAssertEqual(names("+type:login +name:git", in: vault), ["GitHub", "My git repo"])
        XCTAssertEqual(names("+type:login +name:hub", in: vault), ["GitHub"], "every + term must match")
        XCTAssertEqual(names("+type:login -name:hub", in: vault), ["My git repo"])
        XCTAssertEqual(names("+type:login alice", in: vault), ["GitHub", "My git repo"], "plain terms only rank when there is a + term")
    }

    func testPlainTermsAreAlternativesAndLoneExclusionsKeepTheRest() {
        XCTAssertEqual(names("name:hub name:visa", in: vault), ["GitHub", "Alice Visa"], "without + any term may match")
        XCTAssertEqual(names("-type:card", in: vault), ["GitHub", "My git repo", "Digital ID", "Wi-Fi"])
        XCTAssertEqual(names("-type:card -type:login", in: vault), ["Digital ID", "Wi-Fi"])
        XCTAssertEqual(names("name:hub -name:hub", in: vault), [])
    }

    func testMatchingIgnoresCaseAndDiacritics() {
        XCTAssertEqual(names("name:GITHUB", in: vault), ["GitHub"])
        XCTAssertEqual(names("notes:WORK", in: vault), ["GitHub"])
        XCTAssertEqual(names("identity.city:CAFÉ", in: vault), ["Digital ID"])
        XCTAssertEqual(names("identity.city:Caf*", in: vault), ["Digital ID"])
    }

    // MARK: Through the model

    private func model(with items: [VaultItemSummary]) throws -> VaultModel {
        let encoded = try JSONEncoder().encode(items.map(Wire.init))
        let json = #"{"email":"a@example.test","server":"http://127.0.0.1:1","accountId":"\#(UUID().uuidString)","accountHash":"\#(String(repeating: "a", count: 64))","generation":1,"lastSync":null,"items":\#(String(decoding: encoded, as: UTF8.self)),"folders":[{"id":"f-work","name":"Work"},{"id":"f-home","name":"Home"}],"failures":[]}"#
        let model = VaultModel()
        model.loadForTesting(try JSONDecoder().decode(VaultSnapshot.self, from: Data(json.utf8)))
        return model
    }

    /// A summary as the Rust core sends it, so the test also covers decoding `searchFields`.
    private struct Wire: Encodable {
        let id: String, name: String, type: Int, favorite: Bool, folderId: String?, organizationId: String?
        let subtitle: String, searchValues: [String]
        var hasTotp = false, hasPasskey = false, deleted = false, archived = false
        let revisionDate: String, iconHost: String?, searchFields: [String: [String]]
        init(_ item: VaultItemSummary) {
            (id, name, type, favorite, folderId, organizationId) = (item.id, item.name, item.type, item.favorite, item.folderId, nil)
            (subtitle, searchValues, revisionDate, iconHost, searchFields) = (item.subtitle, item.searchValues, item.revisionDate, nil, item.searchFields ?? [:])
        }
    }

    func testModelAppliesAdvancedSearchAndKeepsPlainSearchAsItWas() throws {
        let model = try model(with: vault)
        let shown = { model.visibleItems.map(\.name) }
        model.search = "git"
        XCTAssertEqual(shown(), ["GitHub", "My git repo", "Digital ID"], "plain: substring of name, subtitle or values")
        model.search = "g"
        XCTAssertEqual(shown().count, 5, "one character filters nothing")
        model.search = ">name:git*"
        XCTAssertEqual(shown(), ["GitHub", "My git repo"])
        model.search = ">+folder:Work -type:login"
        XCTAssertEqual(shown(), ["Alice Visa"])
        model.search = ">login.username:bob"
        XCTAssertEqual(shown(), ["My git repo"])
        model.search = "  >  fields.Region:eu "
        XCTAssertEqual(shown(), ["GitHub"], "spaces around the > are fine")
        // The sidebar destination still applies on top of the query.
        model.show(.favorites)
        model.search = ">name:*"
        XCTAssertEqual(shown(), ["Alice Visa"])
        model.show(.all)
        // A query that can't be read matches as plain text after the ">".
        model.search = ">name:\"git"
        XCTAssertEqual(shown(), [])
        model.search = ">wi-fi"
        XCTAssertEqual(shown(), ["Wi-Fi"])
        model.search = ">"
        XCTAssertEqual(shown().count, 5, "a lone > is no filter")
        model.search = "a>b"
        XCTAssertEqual(shown(), [], "a > that isn't first is plain text")
    }

    func testAdvancedSearchOverAThousandsOfItemsStaysFast() throws {
        let many = (0..<5_000).map { index in
            item("Site \(index)", subtitle: "user\(index)", searchValues: ["user\(index)", "https://site\(index).example.com"],
                 fields: ["login.username": ["user\(index)"], "login.uris": ["https://site\(index).example.com"], "notes": ["note \(index)"]])
        }
        let model = try model(with: many)
        model.search = ">+name:site* login.uris:*example* -notes:note*9"
        let start = Date()
        let count = model.visibleItems.count
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertEqual(count, 4_500)
        XCTAssertLessThan(elapsed, 1.0, "took \(Int(elapsed * 1000)) ms")
    }

    /// The real core's list data: field values are there, secrets are not.
    func testSnapshotFromTheServerCarriesSearchableFieldsWithoutSecrets() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["BW_TEST_SERVER"], let email = environment["BW_TEST_EMAIL"],
              let password = environment["BW_TEST_PASSWORD"], environment["BW_TEST_DATA_DIR"] != nil else {
            throw XCTSkip("Disposable test server account is not configured")
        }
        let model = VaultModel()
        try await wait { model.isReady }
        addTeardownBlock { @MainActor in await model.logout() }
        if model.phase == .locked {
            model.password = password
            await model.unlock()
        } else {
            model.email = email
            model.server = server
            model.password = password
            await model.login()
        }
        XCTAssertEqual(model.phase, .unlocked, model.errorMessage ?? "")
        let seed = try XCTUnwrap(model.items.first { $0.name == "Seed Login" })
        let fields = try XCTUnwrap(seed.searchFields)
        XCTAssertEqual(fields["login.username"], ["seed.user@example.com"])
        XCTAssertEqual(fields["login.uris"], ["https://github.com", "https://gist.github.com"])
        XCTAssertEqual(fields["notes"], ["Primary development account."])
        XCTAssertEqual(fields["fields.Region"], ["EU"])
        let everything = String(decoding: try JSONEncoder().encode(fields), as: UTF8.self)
        for secret in ["Seed-Password-1", "alpha-bravo", "JBSWY3DP"] {
            XCTAssertFalse(everything.contains(secret), "\(secret) must not be searchable")
        }
        let card = try XCTUnwrap(model.items.first { $0.name == "Travel Visa" })
        XCTAssertEqual(card.searchFields?["card.brand"], ["Visa"])
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(card.searchFields ?? [:]), as: UTF8.self).contains("4111"))

        let search: (String) -> [String] = { query in model.search = query; return model.visibleItems.map(\.name) }
        XCTAssertTrue(search(">login.username:seed.user").contains("Seed Login"))
        XCTAssertTrue(search(">+folder:Work +type:login").contains("Seed Login"))
        XCTAssertTrue(search(">fields.Region:EU").contains("Seed Login"))
        XCTAssertTrue(search(">name:seed*").contains("Seed Login"))
        XCTAssertTrue(search(">notes:development").contains("Seed Login"))
        XCTAssertFalse(search(">+type:login -folder:Work").contains("Seed Login"))
        XCTAssertFalse(search(">fields:alpha-bravo").contains("Seed Login"), "a hidden field's value is not searchable")
        XCTAssertFalse(search(">Seed-Password-1").contains("Seed Login"), "nor is a password")
        XCTAssertTrue(search(">card.brand:visa").contains("Travel Visa"))
        XCTAssertFalse(search(">4111").contains("Travel Visa"), "nor a card number")
        XCTAssertTrue(search(">identity.firstname:alex").contains("Alex Example"))
    }

    private func wait(timeout: TimeInterval = 15, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            guard Date() < deadline else { throw XCTSkip("Timed out waiting for condition") }
            try await Task.sleep(for: .milliseconds(50))
        }
    }
}
