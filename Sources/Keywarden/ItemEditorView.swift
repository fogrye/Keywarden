import SwiftUI

struct ItemEditorView: View {
    @Bindable var model: VaultModel
    @FocusState private var nameFocused: Bool

    private var editor: Binding<ItemEditor> {
        Binding(get: { model.editor ?? ItemEditor(draft: ItemData(type: 2), original: ItemData(type: 2)) },
                set: { model.editor = $0 })
    }
    private var draft: Binding<ItemData> { editor.draft }

    var body: some View {
        let current = editor.wrappedValue
        Form {
            if let error = model.editorError {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            }
            Section {
                HStack(spacing: 12) {
                    ItemIcon(type: current.draft.kind, size: 32)
                    TextField("Name", text: draft.name, prompt: Text("Name"))
                        .font(.title3)
                        .textFieldStyle(.plain)
                        .focused($nameFocused)
                        .accessibilityLabel("Item name")
                }
                Picker("Folder", selection: draft.folderId) {
                    Text("No Folder").tag(String?.none)
                    ForEach(model.folders) { folder in
                        Text(folder.name).tag(Optional(folder.id))
                    }
                }
                Toggle("Favorite", isOn: draft.favorite)
            }
            typeSections
            FieldsEditor(fields: draft.fields, type: current.draft.kind)
            Section("Notes") {
                TextEditor(text: draft.notes)
                    .font(.body)
                    .frame(minHeight: current.draft.kind == .note ? 220 : 80)
                    .scrollContentBackground(.hidden)
                    .accessibilityLabel("Notes")
            }
            AttachmentsEditorSection(model: model, itemID: current.isNew || current.isClone ? nil : current.original.id,
                                     attachments: current.attachments)
            Section {
                Toggle("Re-authenticate to view", isOn: draft.reprompt)
            } footer: {
                Text("Requires Touch ID or your Mac password before this item is shown.")
            }
        }
        .formStyle(.grouped)
        .disabled(model.isSaving)
        .navigationTitle(current.isClone ? String(localized: "Clone \(current.draft.kind.title)")
                         : current.isNew ? String(localized: "New \(current.draft.kind.title)")
                         : String(localized: "Edit \(current.original.name)"))
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(role: .cancel) {
                    model.navigate { [model] in model.focusRequest = .list }
                } label: {
                    Text("Cancel").padding(.horizontal, 8)
                }
                .keyboardShortcut(.cancelAction)
                Button {
                    Task {
                        await model.saveEditor()
                        if model.editor == nil { model.focusRequest = .list }
                    }
                } label: {
                    // The spinner replaces the title in place, so the toolbar never resizes.
                    Text("Save")
                        .opacity(model.isSaving ? 0 : 1)
                        .overlay { if model.isSaving { ProgressView().controlSize(.small) } }
                        .padding(.horizontal, 10)
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut("s", modifiers: .command)
                .disabled(!current.isValid || !current.isDirty || model.isSaving || model.attachmentActivity != nil)
                .help(current.isValid ? "Save to the server (⌘S)" : "Enter a name to save")
            }
        }
        // Ready to type, whether the editor opened for a new item, an edit (⌘E) or a clone (⌘D).
        .onAppear { nameFocused = true }
        // Asked only while a dirty draft is open, so it lives here. On the split view it stopped
        // the columns' rows from taking keyboard focus.
        .confirmationDialog("Discard unsaved changes?", isPresented: Binding(
            get: { model.pendingNavigation != nil },
            set: { if !$0 { model.pendingNavigation = nil } }
        )) {
            Button("Discard Changes", role: .destructive) {
                let action = model.pendingNavigation
                model.pendingNavigation = nil
                action?()
            }
            Button("Keep Editing", role: .cancel) { model.pendingNavigation = nil }
        } message: {
            Text("Your edits to this item haven’t been saved.")
        }
    }

    @ViewBuilder private var typeSections: some View {
        switch editor.wrappedValue.draft.kind {
        case .login: LoginEditor(login: Binding(get: { draft.wrappedValue.login ?? LoginData() },
                                                set: { draft.wrappedValue.login = $0 }),
                                 removePasskeys: Binding(get: { draft.wrappedValue.removePasskeys ?? false },
                                                         set: { draft.wrappedValue.removePasskeys = $0 ? true : nil }),
                                 passkeys: editor.wrappedValue.passkeys,
                                 model: model,
                                 itemName: editor.wrappedValue.draft.name)
        case .card: CardEditor(card: optionalBinding(\.card, CardData()))
        case .identity: SpecEditor(data: optionalBinding(\.identity, IdentityData()), specs: IdentityData.specs)
        case .bankAccount: SpecEditor(data: optionalBinding(\.bankAccount, BankAccountData()), specs: BankAccountData.specs)
        case .driversLicense: SpecEditor(data: optionalBinding(\.driversLicense, DriversLicenseData()), specs: DriversLicenseData.specs)
        case .passport: SpecEditor(data: optionalBinding(\.passport, PassportData()), specs: PassportData.specs)
        case .sshKey:
            Section {
                Text("SSH key material can’t be changed here. Name, folder, notes and custom fields can.")
                    .foregroundStyle(.secondary)
            }
        case .note: EmptyView()
        }
    }

    private func optionalBinding<Value>(_ path: WritableKeyPath<ItemData, Value?>, _ empty: Value) -> Binding<Value> {
        Binding(get: { draft.wrappedValue[keyPath: path] ?? empty },
                set: { draft.wrappedValue[keyPath: path] = $0 })
    }
}

private struct LoginEditor: View {
    @Binding var login: LoginData
    @Binding var removePasskeys: Bool
    let passkeys: [ItemDetail.Passkey]
    let model: VaultModel
    var itemName = ""
    @State private var generating = false
    @State private var generatingUsername = false

    var body: some View {
        Section {
            HStack(spacing: 6) {
                TextField("Username", text: $login.username)
                    .textContentType(.username)
                    .accessibilityLabel("Username")
                Button {
                    generatingUsername = true
                    let website = login.uris.first?.uri
                    Task {
                        do { login.username = try await model.generateUsername(website: website) }
                        catch { model.editorError = error.localizedDescription }
                        generatingUsername = false
                    }
                } label: {
                    Image(systemName: "wand.and.sparkles").frame(width: 18, height: 18)
                }
                .buttonStyle(.borderless)
                .help("Generate a username")
                .disabled(generatingUsername)
            }
            SecretField(title: String(localized: "Password"), text: $login.password, monospaced: true) {
                Button {
                    generating = true
                    Task {
                        if let password = await model.generatePassword() { login.password = password }
                        generating = false
                    }
                } label: {
                    Image(systemName: "wand.and.sparkles").frame(width: 18, height: 18)
                }
                .buttonStyle(.borderless)
                .help("Generate a password")
                .disabled(generating)
            }
            PasswordStrengthMeter(password: login.password, inputs: [itemName, login.username], email: model.email)
            // The label keeps the body font: SF Mono can't shape Arabic or Indic labels.
            TextField(text: $login.totp, prompt: Text("otpauth:// or secret")) { Text("Authenticator key").font(.body) }
                .font(.body.monospaced())
                .accessibilityLabel("Authenticator key")
            ForEach(passkeys.indices, id: \.self) { index in
                passkeyRow(passkeys[index])
            }
        }
        Section {
            ForEach($login.uris) { $uri in
                HStack {
                    TextField("Website", text: $uri.uri, prompt: Text("https://example.com"))
                        .labelsHidden()
                        .textContentType(.URL)
                        .accessibilityLabel("Website")
                        .accessibilityIdentifier("websiteField")
                    Picker("Match detection", selection: $uri.match) {
                        Text("Default").tag(Int?.none)
                        Divider()
                        ForEach(UriMatch.allCases) { rule in
                            Text(rule.title).tag(Int?.some(rule.rawValue))
                        }
                    }
                    .labelsHidden()
                    .fixedSize()
                    .help("Match detection: how the browser extension decides a page belongs to this website")
                    Button {
                        login.uris.removeAll { $0.id == uri.id }
                    } label: {
                        Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                    }
                    .buttonStyle(.borderless)
                    .help("Remove website")
                }
            }
            Button("Add Website", systemImage: "plus") { login.uris.append(UriData(uri: "")) }
                .buttonStyle(.borderless)
        } header: {
            Text("Websites")
        } footer: {
            Text("Match detection decides which pages the browser extension suggests this login on.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

extension LoginEditor {
    /// Desktop shows "Passkey created <date>" with a remove action; removal happens on save.
    fileprivate func passkeyRow(_ passkey: ItemDetail.Passkey) -> some View {
        HStack {
            Image(systemName: "person.badge.key.fill").foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(removePasskeys ? "Passkey will be removed" : passkeyTitle(passkey))
                    .strikethrough(removePasskeys)
                Text([passkey.userName, passkey.rpId].compactMap { $0 }.joined(separator: " · "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if removePasskeys {
                Button("Undo") { removePasskeys = false }
                    .buttonStyle(.borderless)
            } else {
                Button("Remove", role: .destructive) { removePasskeys = true }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.red)
                    .help("Remove this passkey when you save")
                    .accessibilityIdentifier("removePasskey")
            }
        }
    }

    private func passkeyTitle(_ passkey: ItemDetail.Passkey) -> String {
        if let date = VaultDate.display(passkey.creationDate) { return String(localized: "Passkey created \(date)") }
        return String(localized: "Passkey")
    }
}

private struct SpecEditor<Root>: View {
    @Binding var data: Root
    let specs: [FieldSpec<Root>]

    var body: some View {
        Section {
            ForEach(specs) { spec in
                let text = Binding(get: { data[keyPath: spec.path] ?? "" },
                                   set: { data[keyPath: spec.path] = $0.isEmpty ? nil : $0 })
                if spec.secret {
                    SecretField(title: spec.label, text: text, monospaced: spec.monospaced) { EmptyView() }
                } else {
                    TextField(text: text) { Text(spec.label).font(.body) }
                        .font(spec.monospaced ? .body.monospaced() : .body)
                }
            }
        }
    }
}

/// Name, number (its brand read from the digits), expiry as month and year menus, and the code.
private struct CardEditor: View {
    @Binding var card: CardData

    private func text(_ path: WritableKeyPath<CardData, String?>) -> Binding<String> {
        Binding(get: { card[keyPath: path] ?? "" }, set: { card[keyPath: path] = $0.isEmpty ? nil : $0 })
    }

    private var number: Binding<String> {
        Binding(get: { CardData.grouped(card.number ?? "") }, set: { typed in
            // Shown grouped, stored as digits (pasted dashes dropped); the brand follows the digits.
            let number = typed.filter { $0 != " " && $0 != "-" }
            guard number != (card.number ?? "") else { return }
            card.number = number.isEmpty ? nil : number
            card.brand = CardData.brand(forNumber: number)
        })
    }

    private var month: Binding<String?> {
        // Stored as "1"…"12"; an older "01" reads as the same month.
        Binding(get: { card.expMonth.flatMap { Int($0) }.map(String.init) ?? card.expMonth },
                set: { card.expMonth = $0 })
    }

    private var years: [String] {
        let now = Calendar.current.component(.year, from: .now)
        let upcoming = (now...now + 15).map(String.init)
        guard let year = card.expYear, !upcoming.contains(year) else { return upcoming }
        return [year] + upcoming
    }

    var body: some View {
        Section {
            TextField(text: text(\.cardholderName)) { Text("Cardholder name").font(.body) }
                .textContentType(.name)
            TextField(text: number, prompt: Text(verbatim: "0000 0000 0000 0000")) { Text("Number").font(.body) }
                .font(.body.monospaced())
                .accessibilityLabel("Number")
            // Read-only, and always present so typing never inserts a row.
            LabeledContent("Brand") {
                Text(card.brand.map(CardData.brandTitle) ?? "–")
                    .foregroundStyle(.secondary)
            }
            LabeledContent("Expiration date") {
                HStack(spacing: 6) {
                    Picker("Expiration month", selection: month) {
                        Text(verbatim: "–").tag(String?.none)
                        ForEach(1...12, id: \.self) { index in
                            Text(String(format: "%02d", index) + " – " + Calendar.current.monthSymbols[index - 1])
                                .tag(Optional(String(index)))
                        }
                        if let other = month.wrappedValue, !(1...12).contains(Int(other) ?? 0) {
                            Text(other).tag(Optional(other))
                        }
                    }
                    Picker("Expiration year", selection: $card.expYear) {
                        Text(verbatim: "–").tag(String?.none)
                        ForEach(years, id: \.self) { Text($0).tag(Optional($0)) }
                    }
                }
                .labelsHidden()
                .fixedSize()
            }
            SecretField(title: String(localized: "Security code"), text: text(\.code), monospaced: true) { EmptyView() }
        }
    }
}

private struct FieldsEditor: View {
    @Binding var fields: [FieldData]
    let type: VaultItemType

    private var linkTargets: [(Int, String)] {
        let range: ClosedRange<Int>? = switch type {
        case .login: 100...101
        case .card: 300...305
        case .identity: 400...418
        default: nil
        }
        guard let range else { return [] }
        return LinkedTarget.names.filter { range.contains($0.key) }.sorted { $0.key < $1.key }
    }

    var body: some View {
        Section("Custom Fields") {
            ForEach($fields) { $field in
                HStack(alignment: .firstTextBaseline) {
                    TextField("Name", text: $field.name, prompt: Text("Name"))
                        .labelsHidden()
                        .frame(maxWidth: 160)
                    switch field.kind {
                    case .text:
                        TextField("Value", text: $field.value, prompt: Text("Value")).labelsHidden()
                    case .hidden:
                        SecretField(title: String(localized: "Value"), text: $field.value, labelsHidden: true) { EmptyView() }
                    case .boolean:
                        Toggle("Value", isOn: Binding(get: { field.value == "true" },
                                                      set: { field.value = $0 ? "true" : "false" }))
                            .labelsHidden()
                        Spacer()
                    case .linked:
                        Picker("Linked to", selection: $field.linkedId) {
                            ForEach(linkTargets, id: \.0) { id, name in Text(name).tag(Optional(id)) }
                        }
                        .labelsHidden()
                    }
                    Button {
                        fields.removeAll { $0.id == field.id }
                    } label: {
                        Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                    }
                    .buttonStyle(.borderless)
                    .help("Remove field")
                }
            }
            Menu {
                ForEach(FieldData.Kind.allCases, id: \.rawValue) { kind in
                    if kind != .linked || !linkTargets.isEmpty {
                        Button(kind.title) {
                            fields.append(FieldData(value: kind == .boolean ? "false" : "", type: kind.rawValue,
                                                    linkedId: kind == .linked ? linkTargets.first?.0 : nil))
                        }
                    }
                }
            } label: {
                Label("Add Field", systemImage: "plus")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
    }
}

/// A secure text field with a reveal toggle and optional trailing accessory.
struct SecretField<Accessory: View>: View {
    let title: String
    @Binding var text: String
    var monospaced = false
    var labelsHidden = false
    @ViewBuilder var accessory: Accessory
    @State private var revealed = false

    var body: some View {
        HStack(spacing: 6) {
            Group {
                if revealed {
                    TextField(text: $text) { Text(title).font(.body) }
                        .font(monospaced ? .body.monospaced() : .body)
                } else {
                    SecureField(title, text: $text)
                }
            }
            .accessibilityLabel(title)
            .modifier(HiddenLabel(hidden: labelsHidden))
            Button {
                revealed.toggle()
            } label: {
                Image(systemName: revealed ? "eye.slash" : "eye").frame(width: 18, height: 18)
            }
            .buttonStyle(.borderless)
            .help(revealed ? String(localized: "Hide \(title)") : String(localized: "Show \(title)"))
            accessory
        }
    }
}

private struct HiddenLabel: ViewModifier {
    let hidden: Bool
    func body(content: Content) -> some View {
        if hidden { content.labelsHidden() } else { content }
    }
}

/// Strength of the password being edited, scored by the SDK's zxcvbn (Weak, Good or Strong, like
/// Bitwarden Desktop). The score is computed locally; the password is never logged or sent anywhere.
struct PasswordStrengthMeter: View {
    let password: String
    let inputs: [String]
    let email: String
    @State private var score: Int?

    /// Bitwarden's buckets: 0-2 are Weak (red, red, orange), 3 is Good, 4 is Strong.
    static func label(_ score: Int) -> String {
        score >= 4 ? String(localized: "Strong") : score == 3 ? String(localized: "Good") : String(localized: "Weak")
    }
    static func color(_ score: Int) -> Color {
        switch score { case 4: .green; case 3: .blue; case 2: .orange; default: .red }
    }

    private struct Key: Equatable { let password: String; let inputs: [String]; let email: String }

    var body: some View {
        // The row always exists (empty until scored), so scoring never inserts a row into the form.
        let shown = password.isEmpty ? nil : score
        HStack(spacing: 8) {
            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule().fill(.quaternary)
                    if let shown {
                        Capsule().fill(Self.color(shown))
                            .frame(width: proxy.size.width * CGFloat(shown + 1) / 5)
                    }
                }
            }
            .frame(height: 5)
            Text(shown.map(Self.label) ?? " ")
                .font(.caption.weight(.medium))
                .foregroundStyle(shown.map(Self.color) ?? .secondary)
                .frame(minWidth: 48, alignment: .trailing)
        }
        .opacity(password.isEmpty ? 0 : 1)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Password strength")
        .accessibilityValue(shown.map(Self.label) ?? "")
        .accessibilityHidden(password.isEmpty)
        .accessibilityIdentifier("passwordStrength")
        .task(id: Key(password: password, inputs: inputs, email: email)) {
            guard !password.isEmpty else { score = nil; return }
            // Debounce typing; a newer keystroke cancels this task before the SDK is asked.
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            if let result = try? await SDKClient.shared.passwordStrength(password: password, email: email, inputs: inputs) {
                guard !Task.isCancelled else { return }
                score = min(max(result, 0), 4)
            }
        }
    }
}
