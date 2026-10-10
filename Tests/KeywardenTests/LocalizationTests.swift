import Foundation
import XCTest
@testable import Keywarden

/// Every string in the catalog is translated into each shipped language, and translations keep the
/// source's placeholders, so a prompt such as Touch ID's always names the browser and account.
///
/// A unit's state records where it came from: "translated" is from the Bitwarden clients or checked
/// by a person, "needs_review" was written by AI and not yet checked.
final class LocalizationTests: XCTestCase {
    /// CLDR cardinal plural categories of each shipped language (cldr-json plurals.json).
    static let pluralForms: [String: [String]] = [
        "af": ["one", "other"], "ar": ["zero", "one", "two", "few", "many", "other"], "az": ["one", "other"],
        "be": ["one", "few", "many", "other"], "bg": ["one", "other"], "cs": ["one", "few", "many", "other"],
        "de": ["one", "other"], "es": ["one", "many", "other"], "et": ["one", "other"], "fa": ["one", "other"],
        "fi": ["one", "other"], "fr": ["one", "many", "other"], "hi": ["one", "other"],
        "hr": ["one", "few", "other"], "hu": ["one", "other"], "id": ["other"], "it": ["one", "many", "other"],
        "ja": ["other"], "ko": ["other"], "nl": ["one", "other"], "pl": ["one", "few", "many", "other"],
        "pt-BR": ["one", "many", "other"], "pt-PT": ["one", "many", "other"],
        "ru": ["one", "few", "many", "other"], "sk": ["one", "few", "many", "other"],
        "sr": ["one", "few", "other"], "sv": ["one", "other"], "ta": ["one", "other"], "te": ["one", "other"],
        "th": ["other"], "tr": ["one", "other"], "uk": ["one", "few", "many", "other"], "vi": ["other"],
        "zh-Hans": ["other"], "zh-Hant": ["other"],
    ]
    static var languages: [String] { pluralForms.keys.sorted() }

    private struct Catalog: Decodable {
        struct Entry: Decodable {
            var shouldTranslate: Bool?
            var localizations: [String: Localization]?
        }
        struct Localization: Decodable {
            struct Unit: Decodable { let state: String; let value: String }
            struct Variations: Decodable { let plural: [String: Localization]? }
            var stringUnit: Unit?
            var variations: Variations?
        }
        let sourceLanguage: String
        let strings: [String: Entry]
    }

    private func catalog() throws -> Catalog {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/Keywarden/Localizable.xcstrings")
        return try JSONDecoder().decode(Catalog.self, from: Data(contentsOf: url))
    }

    /// The translated texts of one language: one unit, or one per plural form.
    private func units(_ localization: Catalog.Localization) -> [(form: String, unit: Catalog.Localization.Unit)] {
        if let unit = localization.stringUnit { return [("", unit)] }
        return (localization.variations?.plural ?? [:]).sorted { $0.key < $1.key }.flatMap { form, value in
            units(value).map { (form, $0.unit) }
        }
    }

    /// The placeholders as (position, type), positions counted in order when not given.
    private func placeholders(_ text: String) -> [(position: Int?, type: String)] {
        text.matches(of: /%(?:(\d+)\$)?(lld|@)/).map { ($0.output.1.flatMap { Int($0) }, String($0.output.2)) }
    }

    func testEveryStringIsTranslated() throws {
        var missing: [String] = []
        for (key, entry) in try catalog().strings where entry.shouldTranslate != false {
            for language in Self.languages {
                let texts = entry.localizations?[language].map(units) ?? []
                if texts.isEmpty || texts.contains(where: {
                    !["translated", "needs_review"].contains($0.unit.state) || $0.unit.value.isEmpty
                }) {
                    missing.append("\(language): \(key)")
                }
            }
        }
        XCTAssertEqual(missing.sorted(), [], "Translate these in Localizable.xcstrings")
    }

    /// Same placeholders as the source, and positional ones when there are several, so a translation
    /// can reorder them but never swap, say, the account and the browser in a Touch ID prompt.
    func testTranslationsKeepThePlaceholders() throws {
        var mismatched: [String] = []
        for (key, entry) in try catalog().strings where entry.shouldTranslate != false {
            let expected = placeholders(key).map(\.type)
            for (language, localization) in entry.localizations ?? [:] {
                for (form, unit) in units(localization) {
                    let found = placeholders(unit.value)
                    let ok: Bool
                    if expected.count < 2 {
                        ok = found.map(\.type) == expected && found.allSatisfy { $0.position == nil || $0.position == 1 }
                    } else {
                        let byPosition = Dictionary(found.compactMap { p in p.position.map { ($0, p.type) } },
                                                    uniquingKeysWith: { a, _ in a })
                        ok = found.count == expected.count && found.allSatisfy { $0.position != nil }
                            && byPosition == Dictionary(uniqueKeysWithValues: expected.enumerated().map { ($0 + 1, $1) })
                    }
                    if !ok { mismatched.append("\(language)\(form.isEmpty ? "" : "/\(form)"): \(key) → \(unit.value)") }
                }
            }
        }
        XCTAssertEqual(mismatched.sorted(), [])
    }

    func testPluralKeysCoverEachLanguagesForms() throws {
        var incomplete: [String] = []
        for (key, entry) in try catalog().strings {
            let plurals = (entry.localizations ?? [:]).compactMapValues { $0.variations?.plural }
            guard !plurals.isEmpty else { continue }
            for (language, forms) in Self.pluralForms.merging(["en": ["one", "other"]], uniquingKeysWith: { a, _ in a })
            where !Set(forms).isSubset(of: Set(plurals[language]?.keys.map { $0 } ?? [])) {
                incomplete.append("\(language): \(key)")
            }
        }
        XCTAssertEqual(incomplete.sorted(), [])
    }

    // MARK: Built app

    private func text(_ value: String.LocalizationValue, _ language: String) -> String {
        String(localized: LocalizedStringResource(value, locale: Locale(identifier: language), bundle: .main))
    }

    func testTheAppShipsEachLanguage() {
        let shipped = Set(Bundle.main.localizations)
        XCTAssertEqual(Set(Self.languages).subtracting(shipped), [])
        XCTAssertEqual(text("Unlock", "en"), "Unlock")
        for language in Self.languages {
            XCTAssertNotEqual(text("Unlock the vault first.", language), "Unlock the vault first.", language)
        }
    }

    func testCountsUseEachLanguagesPluralForms() throws {
        XCTAssertEqual([1, 2, 5].map { text("\($0) items", "en") }, ["1 item", "2 items", "5 items"])
        let forms = try XCTUnwrap(catalog().strings["%lld items"]?.localizations)
        // Ukrainian: 1 one, 3 few, 5 many, 21 one. Czech: 1 one, 3 few, 5 other.
        for (language, samples) in ["uk": [(1, "one"), (3, "few"), (5, "many"), (21, "one")],
                                    "cs": [(1, "one"), (3, "few"), (5, "other")]] {
            for (count, form) in samples {
                let format = try XCTUnwrap(forms[language]?.variations?.plural?[form]?.stringUnit?.value)
                XCTAssertEqual(text("\(count) items", language),
                               format.replacingOccurrences(of: "%lld", with: "\(count)"), "\(language) \(count)")
            }
        }
    }

    func testTouchIDPromptNamesTheBrowserAndAccount() {
        let email = "user@example.com", browser = "Firefox"
        for language in Self.languages {
            let reason = text("send the vault key for \(email) to \(browser)", language)
            XCTAssertTrue(reason.contains(email) && reason.contains(browser), "\(language): \(reason)")
        }
    }
}
