import LocalAuthentication
import SwiftUI

/// The right-hand column: the editor while one is open, otherwise the selected item.
struct ItemPane: View {
    @Bindable var model: VaultModel

    var body: some View {
        if model.editor != nil {
            ItemEditorView(model: model)
        } else if let detail = model.detail, detail.id == model.selection {
            ItemDetailView(model: model, detail: detail)
                .id(detail.id)
        } else if model.selection != nil {
            if let error = model.detailError {
                ContentUnavailableView {
                    Label("Can’t Open Item", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(error)
                } actions: {
                    Button("Try Again") { model.reloadDetail() }
                }
            } else {
                ProgressView().controlSize(.small)
            }
        } else {
            ContentUnavailableView("No Item Selected", systemImage: "lock.rectangle.stack",
                                   description: Text("Select an item to see its details."))
        }
    }
}

/// One of the selected item's toolbar buttons: Favorite, Edit and More, or Restore and Delete
/// Permanently for an item in the Trash. They read the list's summary, so they are there at once;
/// the actions that need the decrypted item wait for it.
///
/// The vault's split view declares them, not the detail: a toolbar declared where the content
/// changes (the detail is rebuilt for every item, and shows a spinner while it decrypts) had its
/// buttons replaced, animated, each time the selection moved.
struct ItemToolbarButton: View {
    enum Slot { case first, second, more }
    let model: VaultModel
    let slot: Slot

    var body: some View {
        if let item = model.selectedSummary {
            let editable = model.shownDetail?.editable ?? false
            let locked = model.shownItemLocked
            switch (slot, item.deleted) {
            case (.first, true):
                Button {
                    Task { await model.restoreFromTrash(item.id) }
                } label: {
                    Label("Restore", systemImage: "arrow.uturn.backward")
                }
                .help("Restore from Trash")
            case (.second, true):
                Button(role: .destructive) {
                    model.confirmingDelete = item.id
                } label: {
                    Label("Delete Permanently", systemImage: "trash.slash")
                }
                .help("Delete permanently")
            case (.first, false):
                Button {
                    Task { await model.setFavorite(item.id, !item.favorite) }
                } label: {
                    Label(item.favorite ? "Unfavorite" : "Favorite", systemImage: item.favorite ? "star.fill" : "star")
                }
                .help(item.favorite ? "Remove from Favorites" : "Add to Favorites")
                .disabled(model.isBusy)
            case (.second, false):
                Button {
                    model.beginEditing()
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                // ⌘E is Item › Edit, which also asks for the re-prompt.
                .help(editable || model.shownDetail == nil ? "Edit item (⌘E)" : "You can view but not edit this shared item")
                // Enabled while the item decrypts (editing waits for it anyway): turning it off and on
                // again for those moments made the pencil jump at every selection change.
                .disabled(model.shownDetail?.editable == false || locked)
            case (.more, false):
                Menu {
                    Menu("Move to Folder") {
                        Button("No Folder") { Task { await model.move(item.id, toFolder: nil) } }
                            .disabled(item.folderId == nil)
                        ForEach(model.folders) { folder in
                            Button(folder.name) { Task { await model.move(item.id, toFolder: folder.id) } }
                                .disabled(item.folderId == folder.id)
                        }
                    }
                    if item.kind != .sshKey {
                        Button("Clone", systemImage: "doc.on.doc") { model.beginCloning() }
                            .disabled(locked || model.shownDetail == nil)
                    }
                    Button(item.archived ? "Unarchive" : "Archive", systemImage: "archivebox") {
                        Task { await model.setArchived(item.id, !item.archived) }
                    }
                    Divider()
                    Button("Move to Trash", systemImage: "trash", role: .destructive) {
                        Task { await model.moveToTrash(item.id) }
                    }
                    .disabled(!editable)
                } label: {
                    Label("More", systemImage: "ellipsis.circle")
                }
                .menuIndicator(.hidden)
                .accessibilityIdentifier("moreActions")
                .help("More actions")
            case (.more, true):
                EmptyView()
            }
        }
    }
}

struct ItemDetailView: View {
    let model: VaultModel
    let detail: ItemDetail
    @State private var historyExpanded = false
    /// The row the keyboard is on: one of `detail.copyableFields`, by id.
    @FocusState private var focusedRow: String?

    private var item: ItemData { detail.item }
    private var isTrashed: Bool { detail.deletedDate != nil }
    private var locked: Bool { item.reprompt && model.repromptPassedID != detail.id }

    var body: some View {
        Form {
            header
            if locked {
                Section {
                    VStack(spacing: 10) {
                        Image(systemName: "lock.fill").font(.title).foregroundStyle(.secondary)
                        Text("This item requires re-authentication.")
                        Button("Show Item") { Task { await model.passReprompt() } }
                            .buttonStyle(.borderedProminent)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                }
            } else {
                content
            }
            info
        }
        .formStyle(.grouped)
        // The keyboard walks the rows: ↑/↓ move, ⏎ copies, ← or Esc go back to the list. Space
        // reveals a secret (`ValueRow`).
        .onKeyPress(keys: [.upArrow, .downArrow, .leftArrow, .return]) { press in
            guard let row = focusedRow else { return .ignored }
            let rows = detail.copyableFields
            switch press.key {
            case .return:
                Task { await model.copy(row) }
            case .leftArrow:
                model.focusRequest = .list
            default:
                guard let index = rows.firstIndex(where: { $0.id == row }) else { return .ignored }
                let next = index + (press.key == .downArrow ? 1 : -1)
                if rows.indices.contains(next) { focusedRow = rows[next].id }
            }
            return .handled
        }
        .onExitCommand { if focusedRow != nil { model.focusRequest = .list } }
        .onChange(of: model.focusRequest, initial: true) { _, pane in
            guard pane == .detail else { return }
            model.focusRequest = nil
            Task {
                guard await model.passReprompt() else { return }
                focusedRow = detail.copyableFields.first?.id
            }
        }
    }

    private var header: some View {
        Section {
            HStack(spacing: 14) {
                ItemIcon(type: item.kind, size: 44,
                         url: model.iconURL(model.items.first { $0.id == detail.id }?.iconHost))
                VStack(alignment: .leading, spacing: 3) {
                    Text(item.name)
                        .font(.title2.weight(.semibold))
                        .textSelection(.enabled)
                    Text(headerSubtitle)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 4)
            if isTrashed {
                Label("This item is in the Trash.", systemImage: "trash")
                    .foregroundStyle(.secondary)
            } else if detail.archivedDate != nil {
                HStack {
                    Label("This item is archived.", systemImage: "archivebox")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Unarchive") { Task { await model.setArchived(detail.id, false) } }
                        .disabled(model.isBusy)
                }
            }
        }
    }

    private var headerSubtitle: String {
        var parts = [item.kind.title]
        if let folder = model.folderName(item.folderId) { parts.append(folder) }
        if detail.organizationId != nil { parts.append(String(localized: "Shared")) }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder private var content: some View {
        switch item.kind {
        case .login: loginSections
        case .card: cardSection
        case .identity: specSection(item.identity, IdentityData.specs)
        case .bankAccount: specSection(item.bankAccount, BankAccountData.specs)
        case .driversLicense: specSection(item.driversLicense, DriversLicenseData.specs)
        case .passport: specSection(item.passport, PassportData.specs)
        case .sshKey: sshSection
        case .note: EmptyView()
        }
        if !item.notes.isEmpty {
            Section("Notes") {
                Text(item.notes)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contextMenu { Button("Copy Notes") { SecureClipboard.copy(item.notes) } }
                    .keyboardRow(CopyableField.notes, $focusedRow)
            }
        } else if item.kind == .note {
            Section("Notes") { Text("This note is empty.").foregroundStyle(.secondary) }
        }
        if !item.fields.isEmpty {
            Section("Custom Fields") {
                ForEach(item.fields.indices, id: \.self) { index in fieldRow(item.fields[index], index) }
            }
        }
        if !detail.attachments.isEmpty {
            AttachmentsDetailSection(model: model, itemID: detail.id, attachments: detail.attachments)
        }
        if !detail.passwordHistory.isEmpty {
            // DisclosureGroup inside a grouped Form on macOS ignores clicks, so the toggle is explicit.
            Section {
                Button {
                    withAnimation(.snappy) { historyExpanded.toggle() }
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .rotationEffect(.degrees(historyExpanded ? 90 : 0))
                        Text("Password History (\(detail.passwordHistory.count))")
                        Spacer(minLength: 0)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityValue(historyExpanded ? "Expanded" : "Collapsed")
                if historyExpanded {
                    ForEach(detail.passwordHistory.indices, id: \.self) { index in
                        let entry = detail.passwordHistory[index]
                        ValueRow(label: VaultDate.display(entry.lastUsedDate) ?? String(localized: "Previous"),
                                 value: entry.password, secret: true, monospaced: true)
                    }
                }
            }
        }
    }

    @ViewBuilder private var loginSections: some View {
        let login = item.login ?? LoginData()
        Section {
            if !login.username.isEmpty {
                ValueRow(label: String(localized: "Username"), value: login.username)
                    .keyboardRow(CopyableField.username, $focusedRow)
            }
            if !login.password.isEmpty {
                ValueRow(label: String(localized: "Password"), value: login.password, secret: true, monospaced: true,
                         concealed: !detail.viewPassword)
                    .keyboardRow(CopyableField.password, $focusedRow, enabled: detail.viewPassword)
            }
            if !login.totp.isEmpty {
                TotpRow(model: model, itemID: detail.id)
                    .keyboardRow(CopyableField.totp, $focusedRow)
            }
            ForEach(detail.passkeys.indices, id: \.self) { index in
                let passkey = detail.passkeys[index]
                LabeledContent("Passkey") {
                    Text([passkey.userName, passkey.rpId].compactMap { $0 }.joined(separator: " · "))
                        .foregroundStyle(.secondary)
                }
            }
        }
        if !login.uris.isEmpty {
            Section("Websites") {
                ForEach(login.uris.indices, id: \.self) { index in
                    let uri = login.uris[index]
                    WebsiteRow(uri: uri.uri, match: uri.match.flatMap(UriMatch.init))
                        .keyboardRow(CopyableField.websiteID(index), $focusedRow, enabled: !uri.uri.isEmpty)
                }
            }
        }
    }

    @ViewBuilder private func specSection<Root>(_ data: Root?, _ specs: [FieldSpec<Root>]) -> some View {
        let rows = specs.enumerated().compactMap { index, spec -> (Int, FieldSpec<Root>, String)? in
            guard let data, let value = data[keyPath: spec.path], !value.isEmpty else { return nil }
            return (index, spec, value)
        }
        if !rows.isEmpty {
            Section {
                ForEach(rows, id: \.0) { index, spec, value in
                    ValueRow(label: spec.label, value: value, secret: spec.secret, monospaced: spec.monospaced)
                        .keyboardRow(CopyableField.specID(index), $focusedRow)
                }
            }
        }
    }

    /// The editor's order: name, number, the detected brand, expiry as one row, code.
    @ViewBuilder private var cardSection: some View {
        let rows = (item.card ?? CardData()).fields
        if !rows.isEmpty {
            Section {
                ForEach(rows) { row in
                    let secret = row.kind == .secret
                    ValueRow(label: row.label, value: row.value, secret: secret, monospaced: secret,
                             mask: row.mask, display: row.display)
                        .keyboardRow(row.id, $focusedRow)
                }
            }
        }
    }

    @ViewBuilder private var sshSection: some View {
        if let key = item.sshKey {
            Section {
                ValueRow(label: String(localized: "Fingerprint"), value: key.fingerprint, monospaced: true)
                ValueRow(label: String(localized: "Public key"), value: key.publicKey, monospaced: true, multiline: true)
                ValueRow(label: String(localized: "Private key"), value: key.privateKey, secret: true, monospaced: true, multiline: true)
            }
        }
    }

    @ViewBuilder private func fieldRow(_ field: FieldData, _ index: Int) -> some View {
        let name = field.name.isEmpty ? String(localized: "Field") : field.name
        switch field.kind {
        case .text:
            ValueRow(label: name, value: field.value)
                .keyboardRow(CopyableField.customID(index), $focusedRow, enabled: !field.value.isEmpty)
        case .hidden:
            ValueRow(label: name, value: field.value, secret: true, concealed: !detail.viewPassword)
                .keyboardRow(CopyableField.customID(index), $focusedRow,
                             enabled: !field.value.isEmpty && detail.viewPassword)
        case .boolean:
            LabeledContent(name) {
                Image(systemName: field.value == "true" ? "checkmark.square.fill" : "square")
                    .foregroundStyle(field.value == "true" ? Color.accentColor : .secondary)
                    .accessibilityValue(field.value == "true" ? "On" : "Off")
            }
        case .linked:
            LabeledContent(name) {
                Label(field.linkedId.flatMap { LinkedTarget.names[$0] } ?? String(localized: "Linked"), systemImage: "link")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var info: some View {
        Section {
            if let created = VaultDate.display(detail.creationDate) { LabeledContent("Created", value: created) }
            if let revised = VaultDate.display(detail.revisionDate) { LabeledContent("Modified", value: revised) }
            if let changed = VaultDate.display(detail.passwordRevisionDate) {
                LabeledContent("Password changed", value: changed)
            }
            if let deleted = VaultDate.display(detail.deletedDate) { LabeledContent("Deleted", value: deleted) }
        }
        .font(.callout)
        .foregroundStyle(.secondary)
    }
}

/// A labelled value with copy and, for secrets, reveal controls.
///
/// Don't put `.accessibilityLabel` on text inside `LabeledContent`: SwiftUI resolves the pair's
/// labels through each other, which recursed until the stack overflowed whenever VoiceOver or
/// XCUITest read the detail pane.
struct ValueRow: View {
    let label: String
    let value: String
    var secret = false
    var monospaced = false
    var multiline = false
    /// The item is shared with "hide passwords": show that a value exists but never expose it.
    var concealed = false
    /// What a secret shows while hidden, and the value's revealed form, when not dots and the value.
    var mask: String?
    var display: String?
    /// Set by `keyboardRow`: the row takes keyboard focus, and Space reveals the secret.
    private var keyboard: KeyboardRow?
    @State private var revealed = false
    @State private var hovering = false

    /// This row as one the keyboard reaches (see `View.keyboardRow`), with Space revealing a secret.
    /// The key handler has to sit outside the focusable view, so the row applies both itself.
    func keyboardRow(_ id: String, _ focus: FocusState<String?>.Binding, enabled: Bool = true) -> ValueRow {
        var row = self
        row.keyboard = KeyboardRow(id: id, focus: focus, enabled: enabled)
        return row
    }

    var body: some View {
        if let keyboard {
            row.modifier(keyboard)
                .onKeyPress(.space) {
                    guard secret, !concealed else { return .ignored }
                    revealed.toggle()
                    return .handled
                }
        } else {
            row
        }
    }

    private var row: some View {
        LabeledContent {
            HStack(spacing: 6) {
                valueText
                if !concealed {
                    HStack(spacing: 2) {
                        if secret {
                            iconButton(revealed ? "eye.slash" : "eye",
                                       revealed ? String(localized: "Hide \(label)") : String(localized: "Reveal \(label)")) {
                                revealed.toggle()
                            }
                        }
                        iconButton("doc.on.doc", String(localized: "Copy \(label)")) { SecureClipboard.copy(value) }
                    }
                    .opacity(hovering || revealed ? 1 : 0.35)
                }
            }
        } label: {
            Text(label)
        }
        .onHover { hovering = $0 }
        .contextMenu {
            if !concealed { Button("Copy \(label)") { SecureClipboard.copy(value) } }
        }
    }

    @ViewBuilder private var valueText: some View {
        let shown = secret && (!revealed || concealed)
        Text(shown ? mask ?? String(repeating: "•", count: 10) : display ?? value)
            .font(monospaced && (!shown || mask != nil) ? .body.monospaced() : .body)
            .lineLimit(multiline && !shown ? 12 : 1)
            .truncationMode(.middle)
            .multilineTextAlignment(.trailing)
            .textSelection(.enabled)
            .foregroundStyle(.primary)

    }

    private func iconButton(_ symbol: String, _ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol).frame(width: 18, height: 18)
        }
        .buttonStyle(.borderless)
        .help(title)
        .accessibilityLabel(title)
    }
}

private struct WebsiteRow: View {
    let uri: String
    var match: UriMatch?

    private var url: URL? { UriData.launchURL(uri) }

    var body: some View {
        LabeledContent {
            HStack(spacing: 6) {
                if let url {
                    Link(url.host() ?? uri, destination: url)
                        .lineLimit(1)
                        .help(uri)
                } else {
                    Text(uri).lineLimit(1).textSelection(.enabled)
                }
                Button {
                    SecureClipboard.copy(uri)
                } label: {
                    Image(systemName: "doc.on.doc").frame(width: 18, height: 18)
                }
                .buttonStyle(.borderless)
                .help("Copy website")
            }
        } label: {
            Text("Website")
            if let match {
                Text("Match: \(match.title)")
            }
        }
    }
}

/// Shows the current one-time code with a countdown and refreshes it at each period boundary.
private struct TotpRow: View {
    let model: VaultModel
    let itemID: String
    @State private var code: TotpCode?
    @State private var expiry = Date()
    @State private var failed = false

    var body: some View {
        LabeledContent {
            HStack(spacing: 8) {
                if let code {
                    Text(formatted(code.code))
                        .font(.body.monospacedDigit().weight(.medium))
                        .textSelection(.enabled)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let remaining = max(0, Int(expiry.timeIntervalSince(context.date).rounded(.up)))
                        Text("\(remaining)s")
                            .font(.callout.monospacedDigit())
                            .foregroundStyle(remaining <= 5 ? .red : .secondary)
                            .frame(minWidth: 26, alignment: .trailing)
                    }
                    Button {
                        SecureClipboard.copy(code.code)
                    } label: {
                        Image(systemName: "doc.on.doc").frame(width: 18, height: 18)
                    }
                    .buttonStyle(.borderless)
                    .help("Copy one-time code")
                } else if failed {
                    Text("Invalid key").foregroundStyle(.secondary)
                } else {
                    ProgressView().controlSize(.mini)
                }
            }
        } label: {
            Text("One-time code")
        }
        .task(id: itemID) {
            while !Task.isCancelled {
                do {
                    let next = try await model.totpCode(itemID)
                    code = next
                    expiry = Date().addingTimeInterval(TimeInterval(next.remaining))
                    failed = false
                    try await Task.sleep(for: .seconds(max(1, next.remaining)))
                } catch {
                    if Task.isCancelled { return }
                    failed = true
                    return
                }
            }
        }
    }

    private func formatted(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return "\(code.prefix(3)) \(code.suffix(3))"
    }
}

/// A detail row the keyboard reaches: `ItemDetailView` moves focus between these with the arrow
/// keys. Applied outside the row's `LabeledContent` (see `ValueRow`). Focusable for editing, like a
/// text field, because a plain `focusable()` takes focus only with the system's Keyboard navigation
/// on. The focused row is tinted like a selection instead of drawing the focus ring.
struct KeyboardRow: ViewModifier {
    let id: String
    let focus: FocusState<String?>.Binding
    var enabled = true

    func body(content: Content) -> some View {
        content
            .focusable(enabled, interactions: .edit)
            .focusEffectDisabled()
            .focused(focus, equals: id)
            .background {
                if focus.wrappedValue == id {
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color.accentColor.opacity(0.15))
                        .padding(.horizontal, -6)
                        .padding(.vertical, -4)
                }
            }
    }
}

private extension View {
    func keyboardRow(_ id: String, _ focus: FocusState<String?>.Binding, enabled: Bool = true) -> some View {
        modifier(KeyboardRow(id: id, focus: focus, enabled: enabled))
    }
}

enum Reprompt {
    /// Items flagged "master password re-prompt" are gated behind device-owner authentication.
    /// Tests replace it.
    @MainActor static var authenticate: (_ name: String) async -> Bool = ask

    private static func ask(_ name: String) async -> Bool {
        let context = LAContext()
        do {
            let reason = String(localized: "show “\(name)”", comment: "Touch ID prompt: “Keywarden is trying to …”")
            return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            return false
        }
    }
}
