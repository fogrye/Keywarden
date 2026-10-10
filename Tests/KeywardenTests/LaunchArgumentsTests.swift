import XCTest
@testable import Keywarden

final class LaunchArgumentsTests: XCTestCase {
    func testFoundationLanguageOverridesLaunchTheApp() {
        let arguments = ["-AppleLanguages", "(en)", "-AppleTextDirection", "NO", "-AppleLocale", "en_US"]
        XCTAssertEqual(LaunchCommand.parse(arguments[...]), .app)
    }

    func testFoundationOverridesDoNotChangeExplicitCommands() {
        let cases: [([String], LaunchCommand)] = [
            (["-AppleLocale", "en_US", "--background"], .app),
            (["--quit", "-AppleLocale", "en_US"], .quit),
            (["install", "-AppleLocale", "en_US", "--replace"], .install(replace: true)),
            (["install"], .install(replace: false)),
            (["uninstall", "-NSDocumentRevisionsDebugMode", "YES"], .uninstall),
            (["-SomeNumericPreference", "-1", "--quit"], .quit),
        ]
        for (arguments, expected) in cases {
            XCTAssertEqual(LaunchCommand.parse(arguments[...]), expected, "\(arguments)")
        }
    }

    func testInvalidOrAmbiguousCommandsRemainRejected() {
        for arguments in [
            ["--unknown"], ["unknown"], ["--replace"], ["--quit", "install"],
            ["--background", "--background"], ["install", "--replace", "--replace"],
            ["-AppleLocale"], ["-AppleLocale", "--quit"], ["-"],
        ] {
            XCTAssertNil(LaunchCommand.parse(arguments[...]), "\(arguments)")
        }
    }
}
