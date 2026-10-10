import SwiftUI

/// Generator preferences, remembered between runs and shared with the editor's generate button.
struct GeneratorOptions: Codable, Equatable {
    enum Mode: String, Codable, CaseIterable, Identifiable {
        case password = "Password", passphrase = "Passphrase"
        var id: Self { self }
    }
    var mode = Mode.password
    var length = 20
    var lowercase = true
    var uppercase = true
    var numbers = true
    var special = true
    var avoidAmbiguous = false
    var minNumbers = 1
    var minSpecial = 1
    var numWords = 5
    var separator = "-"
    var capitalize = true
    var includeNumber = true
    /// The window's third type. The editor's password button keeps using `mode`.
    var usernameSelected = false

    static let lengthRange = 8...64
    static let wordRange = 3...10
    static let minimumRange = 0...9

    init() {}

    /// Older builds stored fewer keys; missing ones keep their defaults instead of resetting everything.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        func value<T: Decodable>(_ key: CodingKeys, _ fallback: T) -> T {
            (try? container.decodeIfPresent(T.self, forKey: key)) ?? fallback
        }
        mode = value(.mode, mode)
        length = value(.length, length)
        lowercase = value(.lowercase, lowercase)
        uppercase = value(.uppercase, uppercase)
        numbers = value(.numbers, numbers)
        special = value(.special, special)
        avoidAmbiguous = value(.avoidAmbiguous, avoidAmbiguous)
        minNumbers = value(.minNumbers, minNumbers)
        minSpecial = value(.minSpecial, minSpecial)
        numWords = value(.numWords, numWords)
        separator = value(.separator, separator)
        capitalize = value(.capitalize, capitalize)
        includeNumber = value(.includeNumber, includeNumber)
        usernameSelected = value(.usernameSelected, usernameSelected)
    }

    private static let key = "generatorOptions"

    static var stored: GeneratorOptions {
        guard let data = UserDefaults.standard.data(forKey: key),
              let options = try? JSONDecoder().decode(GeneratorOptions.self, from: data) else { return GeneratorOptions() }
        return options.clamped
    }

    func store() {
        if let data = try? JSONEncoder().encode(self) { UserDefaults.standard.set(data, forKey: Self.key) }
    }

    /// Keeps stored values inside the controls' ranges. The SDK always places at least one character of
    /// every enabled set, so lowercase and uppercase each take one slot, and the minimums for numbers and
    /// special characters can never add up to more than the length allows.
    var clamped: GeneratorOptions {
        var options = self
        options.numWords = min(max(numWords, Self.wordRange.lowerBound), Self.wordRange.upperBound)
        options.length = min(max(length, Self.lengthRange.lowerBound), Self.lengthRange.upperBound)
        options.minNumbers = min(max(minNumbers, Self.minimumRange.lowerBound), Self.minimumRange.upperBound)
        options.minSpecial = min(max(minSpecial, Self.minimumRange.lowerBound), Self.minimumRange.upperBound)
        // Numbers are trimmed first, leaving one slot for special characters; then special characters
        // take what is left. Both keep at least one slot while enabled.
        let room = options.length - (lowercase ? 1 : 0) - (uppercase ? 1 : 0)
        if numbers { options.minNumbers = min(options.minNumbers, max(room - (special ? 1 : 0), 1)) }
        let numberSlots = numbers ? max(options.minNumbers, 1) : 0
        if special { options.minSpecial = min(options.minSpecial, max(room - numberSlots, 1)) }
        return options
    }

    /// Largest value the "minimum" steppers may take right now.
    var maxMinNumbers: Int { max(min(9, length - (lowercase ? 1 : 0) - (uppercase ? 1 : 0) - (special ? max(minSpecial, 1) : 0)), 1) }
    var maxMinSpecial: Int { max(min(9, length - (lowercase ? 1 : 0) - (uppercase ? 1 : 0) - (numbers ? max(minNumbers, 1) : 0)), 1) }

    var isValid: Bool { mode == .passphrase || lowercase || uppercase || numbers || special }

    var request: [String: Any] {
        ["mode": mode == .password ? "password" : "passphrase", "length": length,
         "lowercase": lowercase, "uppercase": uppercase, "numbers": numbers, "special": special,
         "avoidAmbiguous": avoidAmbiguous, "minNumber": minNumbers, "minSpecial": minSpecial,
         "numWords": numWords, "separator": separator,
         "capitalize": capitalize, "includeNumber": includeNumber]
    }
}

private enum GeneratorType: String, CaseIterable, Identifiable {
    case password = "Password", passphrase = "Passphrase", username = "Username"
    var id: Self { self }
    var title: String {
        switch self {
        case .password: String(localized: "Password")
        case .passphrase: String(localized: "Passphrase")
        case .username: String(localized: "Username")
        }
    }
}

struct GeneratorView: View {
    @State private var options = GeneratorOptions.stored.clamped
    @State private var usernameOptions = UsernameOptions.stored
    /// Copy of the stored forwarder secret for the selected service. It is written to the Keychain, never to UserDefaults.
    @State private var token = ""
    @State private var generated = ""
    @State private var failure: String?
    @State private var isGenerating = false
    @State private var requestVersion = 0
    @State private var showsHistory = false
    private let history = GeneratorHistory.shared

    private var type: Binding<GeneratorType> {
        Binding(get: { options.usernameSelected ? .username : (options.mode == .password ? .password : .passphrase) },
                set: { newType in
                    switch newType {
                    case .password: options.usernameSelected = false; options.mode = .password
                    case .passphrase: options.usernameSelected = false; options.mode = .passphrase
                    case .username: options.usernameSelected = true
                    }
                })
    }

    /// Typing a secret saves it to the Keychain straight away; clearing the field removes it.
    private var tokenBinding: Binding<String> {
        Binding(get: { token },
                set: { token = $0; ForwarderSecrets.setToken($0, for: usernameOptions.service) })
    }

    private var currentKind: GeneratorHistory.Kind {
        options.usernameSelected ? .username : (options.mode == .password ? .password : .passphrase)
    }

    private func actions(historyTitled: Bool) -> some View {
        HStack {
            Button(options.usernameSelected && !usernameOptions.generatesAutomatically ? "Generate" : "Regenerate",
                   systemImage: "arrow.clockwise") { generate(explicit: true) }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(isGenerating)
            Spacer()
            let history = Button("History", systemImage: "clock.arrow.circlepath") { showsHistory = true }
            if historyTitled { history } else { history.labelStyle(.iconOnly).help("History") }
            Button("Copy", systemImage: "doc.on.doc") {
                self.history.record(generated, kind: currentKind)
                SecureClipboard.copy(generated)
            }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .buttonStyle(.borderedProminent)
                .disabled(generated.isEmpty)
        }
    }

    private var resultLabel: String {
        switch currentKind {
        case .password: String(localized: "Generated password")
        case .passphrase: String(localized: "Generated passphrase")
        case .username: String(localized: "Generated username")
        }
    }

    var body: some View {
        Form {
            Section {
                Text(generated.isEmpty ? " " : generated)
                    .font(.title3.monospaced())
                    .textSelection(.enabled)
                    .lineLimit(3)
                    .minimumScaleFactor(0.6)
                    .frame(maxWidth: .infinity, minHeight: 56)
                    .multilineTextAlignment(.center)
                    .accessibilityLabel(generated.isEmpty ? String(localized: "No result") : resultLabel)
                // Where the labels don't fit (longer languages), History shows only its icon.
                ViewThatFits(in: .horizontal) {
                    actions(historyTitled: true)
                    actions(historyTitled: false)
                }
                if let failure {
                    Text(failure).foregroundStyle(.red)
                }
            }
            Section {
                Picker("Type", selection: type) {
                    ForEach(GeneratorType.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                if options.usernameSelected {
                    UsernameOptionsForm(options: $usernameOptions, token: tokenBinding)
                } else if options.mode == .password {
                    LabeledContent("Length") {
                        HStack {
                            Slider(value: Binding(get: { Double(options.length) },
                                                  set: { options.length = Int($0.rounded()) }),
                                   in: Double(GeneratorOptions.lengthRange.lowerBound)...Double(GeneratorOptions.lengthRange.upperBound))
                            Text("\(options.length)").monospacedDigit().frame(width: 26, alignment: .trailing)
                        }
                    }
                    Toggle("A–Z", isOn: $options.uppercase)
                    Toggle("a–z", isOn: $options.lowercase)
                    Toggle("0–9", isOn: $options.numbers)
                    Toggle("!@#$%^&*", isOn: $options.special)
                    LabeledContent("Minimum numbers") {
                        Stepper(value: $options.minNumbers, in: 0...options.maxMinNumbers) {
                            Text("\(options.minNumbers)").monospacedDigit()
                        }
                    }
                    .disabled(!options.numbers)
                    LabeledContent("Minimum special") {
                        Stepper(value: $options.minSpecial, in: 0...options.maxMinSpecial) {
                            Text("\(options.minSpecial)").monospacedDigit()
                        }
                    }
                    .disabled(!options.special)
                    Toggle("Avoid ambiguous characters", isOn: $options.avoidAmbiguous)
                } else {
                    LabeledContent("Words") {
                        HStack {
                            Slider(value: Binding(get: { Double(options.numWords) },
                                                  set: { options.numWords = Int($0.rounded()) }),
                                   in: Double(GeneratorOptions.wordRange.lowerBound)...Double(GeneratorOptions.wordRange.upperBound))
                            Text("\(options.numWords)").monospacedDigit().frame(width: 26, alignment: .trailing)
                        }
                    }
                    TextField("Separator", text: $options.separator)
                    Toggle("Capitalize", isOn: $options.capitalize)
                    Toggle("Include number", isOn: $options.includeNumber)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 400)
        .fixedSize(horizontal: false, vertical: true)
        .onAppear {
            token = ForwarderSecrets.token(for: usernameOptions.service) ?? ""
            generate()
        }
        .onChange(of: options) { _, options in
            let clamped = options.clamped
            if clamped != options { self.options = clamped; return }
            options.store()
            generate()
        }
        .onChange(of: usernameOptions) { _, changed in
            let tidy = changed.clamped
            if tidy != changed { usernameOptions = tidy; return }
            changed.store()
            generate()
        }
        .onChange(of: usernameOptions.service) { _, service in token = ForwarderSecrets.token(for: service) ?? "" }
        .sheet(isPresented: $showsHistory) { GeneratorHistoryView() }
        .onDisappear {
            generated = ""
            failure = nil
            token = ""
        }
    }

    /// `explicit` marks a click on Generate or Regenerate. Aliases from an email forwarder are created only
    /// then, never as a side effect of opening the window or editing an option.
    private func generate(explicit: Bool = false) {
        requestVersion += 1
        let version = requestVersion
        if options.usernameSelected {
            guard explicit || (usernameOptions.generatesAutomatically && usernameOptions.isReady) else {
                generated = ""
                failure = nil
                isGenerating = false
                return
            }
            let request = usernameOptions.request(token: usernameOptions.kind == .forwarded ? token : nil)
            run(version, record: explicit) { try await SDKClient.shared.generateUsername(options: request) }
        } else {
            guard options.isValid else { generated = ""; failure = nil; return }
            let request = options.request
            run(version, record: explicit) { try await SDKClient.shared.generate(options: request) }
        }
    }

    private func run(_ version: Int, record: Bool, _ operation: @escaping () async throws -> String) {
        isGenerating = true
        Task {
            do {
                let value = try await operation()
                guard version == requestVersion else { return }
                generated = value
                failure = nil
                // Options changes regenerate constantly; only a click on Generate or Regenerate is kept.
                if record { history.record(value, kind: currentKind) }
            } catch {
                guard version == requestVersion else { return }
                generated = ""
                failure = (error as? VaultError)?.message ?? String(localized: "Couldn’t generate with these options.")
            }
            isGenerating = false
        }
    }
}

/// The username settings. Everything here is a plain field except the forwarder token.
private struct UsernameOptionsForm: View {
    @Binding var options: UsernameOptions
    @Binding var token: String

    var body: some View {
        Picker("Username type", selection: $options.kind) {
            ForEach(UsernameOptions.Kind.allCases) { Text($0.title).tag($0) }
        }
        switch options.kind {
        case .word:
            Toggle("Capitalize", isOn: $options.capitalize)
            Toggle("Include number", isOn: $options.includeNumber)
        case .plusAddressed:
            TextField("Email", text: $options.email, prompt: Text("you@example.com"))
                .textContentType(.emailAddress)
            Text("Adds a random tag, like you+abc12xyz@example.com.").font(.caption).foregroundStyle(.secondary)
        case .catchAll:
            TextField("Domain", text: $options.catchAllDomain, prompt: Text("example.com"))
            Text("Mail to any name at your domain reaches you.").font(.caption).foregroundStyle(.secondary)
        case .forwarded:
            Picker("Service", selection: $options.service) {
                ForEach(ForwarderService.allCases) { Text($0.title).tag($0) }
            }
            SecureField(options.service.secretTitle, text: $token)
            forwarderFields
            Text("Each Generate creates a new alias with \(options.service.title). The \(options.service.secretTitle) stays in the Keychain.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var forwarderFields: some View {
        switch options.service {
        case .simpleLogin:
            TextField("Server URL", text: $options.simpleLoginURL, prompt: Text("https://app.simplelogin.io"))
        case .addy:
            TextField("Server URL", text: $options.addyURL, prompt: Text("https://app.addy.io"))
            TextField("Domain", text: $options.addyDomain, prompt: Text("anonaddy.me"))
        case .forwardEmail:
            TextField("Domain", text: $options.forwardEmailDomain, prompt: Text("example.com"))
        case .firefoxRelay, .fastmail, .duckDuckGo:
            EmptyView()
        }
    }
}

/// Past generated values, newest first. They are listed only while the vault is unlocked.
private struct GeneratorHistoryView: View {
    private let history = GeneratorHistory.shared
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Generator history").font(.headline)
                Spacer()
                Button("Clear All", role: .destructive) { history.clear() }
                    .disabled(history.entries.isEmpty)
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding()
            Divider()
            if !history.isVisible {
                ContentUnavailableView("Vault locked", systemImage: "lock",
                                       description: Text(lockedDescription))
            } else if history.entries.isEmpty {
                ContentUnavailableView("No history yet", systemImage: "clock.arrow.circlepath",
                                       description: Text("Values you generate or copy appear here until you log out or quit."))
            } else {
                List(history.entries) { entry in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.value)
                                .font(.body.monospaced())
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .textSelection(.enabled)
                            Text(verbatim: "\(entry.kind.title) · \(entry.date.formatted(date: .abbreviated, time: .standard))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Copy", systemImage: "doc.on.doc") { SecureClipboard.copy(entry.value) }
                            .labelStyle(.iconOnly)
                            .buttonStyle(.borderless)
                            .help("Copy")
                    }
                }
            }
        }
        .frame(width: 400, height: 360)
    }

    private var lockedDescription: String {
        let count = history.entries.count
        let saved = count == 0 ? String(localized: "Nothing is saved yet.") : String(localized: "\(count) saved values.")
        return String(localized: "Unlock the vault to see generator history. \(saved)")
    }
}
