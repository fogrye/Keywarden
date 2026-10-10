import Foundation
import XCTest
@testable import Keywarden

@MainActor
final class GeneratorOptionsTests: XCTestCase {
    func testRangesStayAsShipped() {
        XCTAssertEqual(GeneratorOptions.lengthRange, 8...64)
        XCTAssertEqual(GeneratorOptions.wordRange, 3...10)
        var options = GeneratorOptions()
        options.length = 500
        options.numWords = 99
        XCTAssertEqual(options.clamped.length, 64)
        XCTAssertEqual(options.clamped.numWords, 10)
        options.length = 1
        options.numWords = 0
        XCTAssertEqual(options.clamped.length, 8)
        XCTAssertEqual(options.clamped.numWords, 3)
    }

    func testMinimumsNeverExceedTheLength() {
        var options = GeneratorOptions()
        options.length = 8
        options.minNumbers = 9
        options.minSpecial = 9
        let clamped = options.clamped
        XCTAssertLessThanOrEqual(clamped.minNumbers + clamped.minSpecial, clamped.length)
        // Lowercase and uppercase keep one slot each, and each enabled set keeps at least one.
        XCTAssertLessThanOrEqual(clamped.minNumbers + clamped.minSpecial, clamped.length - 2)
        XCTAssertGreaterThanOrEqual(clamped.minNumbers, 1)
        XCTAssertGreaterThanOrEqual(clamped.minSpecial, 1)
        options.minNumbers = 20
        options.minSpecial = -4
        XCTAssertEqual(options.clamped.minNumbers, 5)
        XCTAssertEqual(options.clamped.minSpecial, 0)
        options.length = 64
        options.minNumbers = 9
        options.minSpecial = 9
        XCTAssertEqual(options.clamped.minNumbers, 9)
        XCTAssertEqual(options.clamped.minSpecial, 9)
    }

    func testMinimumsOfDisabledSetsDoNotConsumeRoom() {
        var options = GeneratorOptions()
        options.length = 8
        options.special = false
        options.minNumbers = 9
        options.minSpecial = 9
        XCTAssertEqual(options.clamped.minNumbers, 6)
        XCTAssertTrue(options.clamped.request["special"] as? Bool == false)
    }

    func testStepperLimitsFollowTheOtherMinimum() {
        var options = GeneratorOptions()
        options.length = 20
        options.minSpecial = 4
        XCTAssertEqual(options.maxMinNumbers, 9)
        options.length = 8
        XCTAssertEqual(options.maxMinNumbers, 2)
        options.minSpecial = 1
        XCTAssertEqual(options.maxMinNumbers, 5)
    }

    func testStoredOptionsFromOlderBuildsKeepTheirValues() throws {
        let legacy = #"{"mode":"Passphrase","length":30,"lowercase":true,"uppercase":false,"numbers":true,"special":true,"avoidAmbiguous":true,"numWords":7,"separator":".","capitalize":false,"includeNumber":false}"#
        let options = try JSONDecoder().decode(GeneratorOptions.self, from: Data(legacy.utf8))
        XCTAssertEqual(options.mode, .passphrase)
        XCTAssertEqual(options.length, 30)
        XCTAssertEqual(options.numWords, 7)
        XCTAssertEqual(options.separator, ".")
        XCTAssertEqual(options.minNumbers, 1)
        XCTAssertEqual(options.minSpecial, 1)
    }

    func testRequestCarriesMinimumsAndTheSDKHonoursThem() async throws {
        var options = GeneratorOptions()
        options.length = 24
        options.minNumbers = 6
        options.minSpecial = 5
        let request = options.clamped.request
        XCTAssertEqual(request["minNumber"] as? Int, 6)
        XCTAssertEqual(request["minSpecial"] as? Int, 5)
        for _ in 0..<10 {
            let value = try await SDKClient.shared.generate(options: request)
            XCTAssertEqual(value.count, 24)
            XCTAssertGreaterThanOrEqual(value.filter(\.isNumber).count, 6)
            XCTAssertGreaterThanOrEqual(value.filter { "!@#$%^&*".contains($0) }.count, 5)
        }
    }
}
