@testable import Keywarden
import XCTest

final class ServerRegionTests: XCTestCase {
    func testInfersRegionFromSignInAndAPIAddresses() {
        XCTAssertEqual(ServerRegion(server: ""), .us)
        XCTAssertEqual(ServerRegion(server: "https://bitwarden.com"), .us)
        XCTAssertEqual(ServerRegion(server: "https://api.bitwarden.com"), .us)
        XCTAssertEqual(ServerRegion(server: "https://bitwarden.eu"), .eu)
        XCTAssertEqual(ServerRegion(server: "https://api.bitwarden.eu"), .eu)
        XCTAssertEqual(ServerRegion(server: "https://vault.example.com"), .selfHosted)
        XCTAssertEqual(ServerRegion(server: "http://127.0.0.1:18088/api"), .selfHosted)
    }

    func testCloudRegionsSignInWithAddressesTheSDKBridgeKnows() {
        XCTAssertEqual(ServerRegion.us.server, "")
        XCTAssertEqual(ServerRegion.eu.server, "https://bitwarden.eu")
        XCTAssertNil(ServerRegion.selfHosted.server)
    }

    func testDisplayHost() {
        XCTAssertEqual(ServerRegion.displayHost("https://api.bitwarden.com"), "bitwarden.com")
        XCTAssertEqual(ServerRegion.displayHost("https://api.bitwarden.eu"), "bitwarden.eu")
        XCTAssertEqual(ServerRegion.displayHost("https://vault.example.com/api"), "vault.example.com")
    }
}
