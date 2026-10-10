import AppKit
import SwiftUI

struct RootView: View {
    @Bindable var model: VaultModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            switch model.phase {
            case .loading:
                ProgressView()
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .keepsToolbarHeight()
            case .loggedOut, .locked:
                LoginView(model: model)
                    .keepsToolbarHeight()
            case .unlocked:
                VaultSplitView(model: model)
            }
        }
        .frame(minWidth: 780, minHeight: 480)
        .alert("Keywarden", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
        .onAppear { model.refreshIfStale() }
    }
}

private extension View {
    /// An empty toolbar, so the window's title bar is as tall as the vault's and the window
    /// buttons don't move when the lock screen gives way to the vault.
    func keepsToolbarHeight() -> some View {
        toolbar { ToolbarSpacer(.flexible) }
    }
}

private struct VaultSplitView: View {
    @Bindable var model: VaultModel
    @State private var columns = NavigationSplitViewVisibility.all
    @FocusState private var searchFocused: Bool
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView(columnVisibility: $columns) {
            SidebarView(model: model, newFolder: $model.newFolderRequested)
                .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 280)
        } content: {
            ItemListView(model: model)
                .navigationSplitViewColumnWidth(min: 240, ideal: 300, max: 420)
        } detail: {
            ItemPane(model: model)
                .navigationSplitViewColumnWidth(min: 360, ideal: 460)
        }
        .searchable(text: $model.search, placement: .toolbar, prompt: "Search")
        .searchFocused($searchFocused)
        // ⏎ goes to the results: the first one is selected unless a visible one already is.
        .onSubmit(of: .search) {
            let items = model.visibleItems
            if !items.contains(where: { $0.id == model.selection }), let first = items.first { model.select(first.id) }
            model.focusRequest = .list
        }
        .modifier(SearchArrowKeys(model: model))
        // The vault opens ready to type a search, unless it opened for a new item (⌘N).
        .task {
            if model.editor == nil { searchFocused = true }
            if model.focusRequest == .search { model.focusRequest = nil }
        }
        .onChange(of: model.focusRequest) { _, pane in
            guard pane == .search else { return }
            searchFocused = true
            model.focusRequest = nil
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Menu {
                    ForEach(VaultItemType.creatable) { type in
                        Button(type.title, systemImage: type.symbol) { model.beginNewItem(type) }
                    }
                    Divider()
                    Button("Folder", systemImage: "folder.badge.plus") { model.newFolderRequested = true }
                } label: {
                    Label("New Item", systemImage: "plus")
                }
                .menuIndicator(.hidden)
                .accessibilityIdentifier("newItem")
                .help("Create a new item")
                .disabled(model.isBusy)
            }
            ToolbarItem(placement: .navigation) {
                Button {
                    Task { await model.sync() }
                } label: {
                    Label("Sync", systemImage: "arrow.triangle.2.circlepath")
                        .symbolEffect(.rotate, isActive: model.isSyncing)
                }
                .help(syncHelp)
                .disabled(model.isSyncing)
            }
            if model.editor == nil, model.selection != nil {
                ToolbarItem(placement: .primaryAction) { ItemToolbarButton(model: model, slot: .first) }
                ToolbarItem(placement: .primaryAction) { ItemToolbarButton(model: model, slot: .second) }
                ToolbarItem(placement: .primaryAction) { ItemToolbarButton(model: model, slot: .more) }
            }
        }
        .sheet(isPresented: $model.newFolderRequested) {
            FolderNameSheet(title: String(localized: "New Folder"), initial: "") { name in
                await model.saveFolder(id: nil, name: name)
            }
        }
        .sheet(isPresented: $model.exportRequested) {
            ExportSheet(model: model)
        }
        .sheet(isPresented: $model.importRequested) {
            ImportSheet(model: model)
        }
    }

    private var syncHelp: String {
        if let error = model.syncError { return String(localized: "Last sync failed: \(error)") }
        guard let lastSync = model.lastSync else { return String(localized: "Sync with the server") }
        return String(localized: "Last synced \(lastSync.formatted(.relative(presentation: .named)))")
    }
}

/// ↓/↑ while typing a search walk the results and leave focus in the search field. The toolbar
/// field is AppKit's, and its editor takes arrow keys before SwiftUI's key handlers see them, so
/// this watches the app's key events for this view's window.
private struct SearchArrowKeys: ViewModifier {
    let model: VaultModel
    @State private var monitor = EventMonitor()
    @State private var window = WeakWindow()

    func body(content: Content) -> some View {
        content
            .background(WindowReader(window: window))
            .onAppear {
                guard monitor.token == nil else { return }
                monitor.token = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [model, window] event in
                    let offset = switch event.keyCode { case 125: 1; case 126: -1; default: 0 }
                    guard offset != 0, event.modifierFlags.intersection([.shift, .control, .option, .command]).isEmpty
                    else { return event }
                    let target = event.window
                    let handled = MainActor.assumeIsolated {
                        guard let own = window.value, target === own,
                              (own.firstResponder as? NSTextView)?.delegate is NSSearchField else { return false }
                        model.selectAdjacent(offset)
                        return true
                    }
                    return handled ? nil : event
                }
            }
            .onDisappear {
                monitor.token = nil
            }
    }
}

/// An installed local event monitor, removed when replaced, cleared or released. A closed window
/// may never send `onDisappear`, so releasing the view's state must remove it too.
private final class EventMonitor {
    var token: Any? { didSet { if let oldValue { NSEvent.removeMonitor(oldValue) } } }
    deinit { if let token { NSEvent.removeMonitor(token) } }
}

/// The window a view is in, without keeping it alive.
@MainActor private final class WeakWindow {
    weak var value: NSWindow?
}

private struct WindowReader: NSViewRepresentable {
    let window: WeakWindow
    func makeNSView(context: Context) -> NSView { Reader(window) }
    func updateNSView(_ view: NSView, context: Context) {}

    private final class Reader: NSView {
        let target: WeakWindow
        init(_ target: WeakWindow) {
            self.target = target
            super.init(frame: .zero)
        }
        required init?(coder: NSCoder) { nil }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            target.value = window
        }
    }
}

private struct SidebarView: View {
    @Bindable var model: VaultModel
    @Binding var newFolder: Bool

    private var selection: Binding<SidebarItem?> {
        Binding(get: { model.destination }, set: { if let place = $0 { model.show(place) } })
    }

    var body: some View {
        List(selection: selection) {
            Section {
                row(String(localized: "All Items"), "square.grid.2x2", .all)
                row(String(localized: "Favorites"), "star", .favorites)
            }
            let types = model.sidebarTypes
            if !types.isEmpty {
                Section("Types") {
                    ForEach(types) { type in
                        row(type.pluralTitle, type.symbol, .type(type))
                    }
                }
            }
            Section("Folders") {
                ForEach(model.folders) { folder in
                    row(folder.name, "folder", .folder(folder.id))
                        .contextMenu {
                            Button("Rename…") { model.renamingFolder = folder }
                            Button("Delete Folder…", role: .destructive) { model.deletingFolder = folder }
                        }
                }
                row(String(localized: "No Folder"), "tray", .noFolder)
            }
            Section {
                row(String(localized: "Archive"), "archivebox", .archive)
                row(String(localized: "Trash"), "trash", .trash)
            }
        }
        .contextMenu {
            Button("New Folder…") { newFolder = true }
        }
        .safeAreaInset(edge: .bottom) {
            SyncStatus(model: model)
        }
        .sheet(item: $model.renamingFolder) { folder in
            FolderNameSheet(title: String(localized: "Rename Folder"), initial: folder.name) { name in
                await model.saveFolder(id: folder.id, name: name)
            }
        }
        .confirmationDialog("Delete “\(model.deletingFolder?.name ?? "")”?", isPresented: Binding(
            get: { model.deletingFolder != nil }, set: { if !$0 { model.deletingFolder = nil } }
        ), presenting: model.deletingFolder) { folder in
            Button("Delete Folder", role: .destructive) { Task { await model.deleteFolder(folder.id) } }
        } message: { _ in
            Text("Items in this folder are kept and moved to No Folder.")
        }
    }

    private func row(_ title: String, _ symbol: String, _ place: SidebarItem) -> some View {
        let count = model.count(place)
        return Label(title, systemImage: symbol)
            .badge(count)
            .tag(place)
    }
}

private struct SyncStatus: View {
    let model: VaultModel

    var body: some View {
        HStack(spacing: 6) {
            if model.isSyncing {
                ProgressView().controlSize(.mini)
                Text("Syncing…")
            } else if model.syncError != nil {
                Image(systemName: "exclamationmark.icloud").foregroundStyle(.orange)
                Text("Offline — showing saved vault")
            } else if let lastSync = model.lastSync {
                Text("Synced \(lastSync, format: .relative(presentation: .named))")
            }
            Spacer(minLength: 0)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .help(model.syncError ?? "")
    }
}

struct FolderNameSheet: View {
    let title: String
    let initial: String
    let save: (String) async -> Bool
    @State private var name = ""
    @State private var saving = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title).font(.headline)
            TextField("Folder name", text: $name)
                .textFieldStyle(.roundedBorder)
                .onSubmit(submit)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(saving || trimmed.isEmpty || trimmed == initial)
            }
        }
        .padding(20)
        .frame(width: 340)
        .onAppear { name = initial }
    }

    private var trimmed: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func submit() {
        guard !saving, !trimmed.isEmpty, trimmed != initial else { return }
        saving = true
        Task {
            if await save(trimmed) { dismiss() }
            saving = false
        }
    }
}
