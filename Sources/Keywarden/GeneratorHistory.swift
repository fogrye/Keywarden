import Foundation
import Observation

/// Values produced by the generator, newest first. History is secret, so it lives only in memory:
/// nothing is written to disk, it is shown only while the vault is unlocked, and it is wiped on logout
/// or quit. Values generated while the vault is locked are recorded too and appear after unlocking.
@MainActor @Observable
final class GeneratorHistory {
    static let shared = GeneratorHistory()
    static let capacity = 100

    enum Kind: String, Sendable {
        case password = "Password", passphrase = "Passphrase", username = "Username"
        var title: String {
            switch self {
            case .password: String(localized: "Password")
            case .passphrase: String(localized: "Passphrase")
            case .username: String(localized: "Username")
            }
        }
    }

    struct Entry: Identifiable, Equatable {
        let id = UUID()
        let value: String
        let kind: Kind
        let date: Date
    }

    private(set) var entries: [Entry] = []
    /// Entries may be shown only while the vault is unlocked; `VaultModel` keeps this current.
    private(set) var isVisible = false

    init() {}

    /// Follows the vault: unlocking shows the history, locking hides it, and logging out wipes it.
    func sessionChanged(unlocked: Bool, loggedOut: Bool = false) {
        isVisible = unlocked
        if loggedOut { clear() }
    }

    /// Records a value unless it is empty or repeats the newest entry.
    func record(_ value: String, kind: Kind, date: Date = Date()) {
        guard !value.isEmpty, entries.first?.value != value else { return }
        entries.insert(Entry(value: value, kind: kind, date: date), at: 0)
        if entries.count > Self.capacity { entries.removeLast(entries.count - Self.capacity) }
    }

    func clear() { entries.removeAll() }
}
