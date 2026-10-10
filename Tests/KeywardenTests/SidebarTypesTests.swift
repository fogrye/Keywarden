import XCTest
@testable import Keywarden

/// The sidebar's Types section lists only the types that have items.
@MainActor
final class SidebarTypesTests: XCTestCase {
    private func item(_ type: VaultItemType, deleted: Bool = false, archived: Bool = false) -> VaultItemSummary {
        VaultItemSummary(id: UUID().uuidString, name: "Item", type: type.rawValue, favorite: false, folderId: nil,
                         organizationId: nil, subtitle: "", searchValues: [], hasTotp: false, hasPasskey: false,
                         deleted: deleted, archived: archived, revisionDate: "2026-01-01T00:00:00Z", iconHost: nil)
    }

    func testOnlyTypesWithItemsAreListed() {
        let items = [item(.card), item(.login), item(.login)]
        XCTAssertEqual(VaultModel.sidebarTypes(items, showing: .all), [.login, .card])
    }

    func testAnEmptyVaultListsNoTypes() {
        XCTAssertEqual(VaultModel.sidebarTypes([], showing: .all), [])
    }

    func testTrashedAndArchivedItemsDontCount() {
        let items = [item(.login), item(.card, deleted: true), item(.passport, archived: true)]
        XCTAssertEqual(VaultModel.sidebarTypes(items, showing: .trash), [.login])
    }

    func testTheShownTypeStaysListedWhenItsLastItemGoes() {
        let items = [item(.login), item(.card, deleted: true)]
        XCTAssertEqual(VaultModel.sidebarTypes(items, showing: .type(.card)), [.login, .card])
    }
}
