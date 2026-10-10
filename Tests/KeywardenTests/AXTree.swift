import AppKit
import ApplicationServices
import SwiftUI
import XCTest

/// A flattened copy of the accessibility tree AppKit exposes for a hosted SwiftUI view: what
/// VoiceOver and XCUITest read. It lets in-process tests assert on visible labels, values,
/// identifiers and enabled state, and press controls, without a separate app process.
///
/// SwiftUI builds its accessibility tree only once an accessibility client is active. XCUITest is
/// one; a hosted test is not, so `HostedWindow` switches it on first.
@MainActor
struct AXTree {
    struct Node {
        let role: String
        let label: String
        let value: String
        let identifier: String
        let enabled: Bool
        let depth: Int
        let element: NSObject

        var text: String { [label, value].filter { !$0.isEmpty }.joined(separator: " ") }
    }

    let nodes: [Node]

    init(_ root: NSObject, maxDepth: Int = 80) {
        var collected: [Node] = []
        var seen = Set<ObjectIdentifier>()
        func visit(_ object: NSObject, _ depth: Int) {
            guard depth < maxDepth, seen.insert(ObjectIdentifier(object)).inserted else { return }
            let role = Self.attribute(object, "AXRole", "accessibilityRole") as? String ?? ""
            let label = Self.attribute(object, "AXDescription", "accessibilityLabel") as? String ?? ""
            let title = Self.attribute(object, "AXTitle", "accessibilityTitle") as? String ?? ""
            let value = Self.attribute(object, "AXValue", "accessibilityValue").map { "\($0)" } ?? ""
            let placeholder = Self.attribute(object, "AXPlaceholderValue", "accessibilityPlaceholderValue") as? String ?? ""
            let identifier = Self.attribute(object, "AXIdentifier", "accessibilityIdentifier") as? String ?? ""
            let enabled = (Self.attribute(object, "AXEnabled", "accessibilityEnabled") as? NSNumber)?.boolValue ?? true
            collected.append(Node(role: role, label: !label.isEmpty ? label : (!title.isEmpty ? title : placeholder), value: value,
                                  identifier: identifier, enabled: enabled, depth: depth, element: object))
            for child in Self.attribute(object, "AXChildren", "accessibilityChildren") as? [Any] ?? [] {
                if let child = child as? NSObject { visit(child, depth + 1) }
            }
        }
        visit(root, 0)
        nodes = collected
    }

    /// SwiftUI's nodes answer either the modern accessibility methods or the legacy attribute call,
    /// depending on the node; ask both.
    fileprivate static func attribute(_ object: NSObject, _ legacy: String, _ modern: String) -> Any? {
        // Boolean properties are read through their `is` getter.
        let getter = modern == "accessibilityEnabled" ? "isAccessibilityEnabled" : modern
        if object.responds(to: Selector(getter)), let value = object.value(forKey: modern) { return value }
        let selector = NSSelectorFromString("accessibilityAttributeValue:")
        guard object.responds(to: selector) else { return nil }
        return object.perform(selector, with: legacy)?.takeUnretainedValue()
    }

    /// Every label, title and value the tree carries.
    var texts: [String] { nodes.map(\.text).filter { !$0.isEmpty } }

    /// True when some element is labelled, titled or valued exactly `text`.
    func contains(_ text: String) -> Bool {
        nodes.contains { $0.label == text || $0.value == text }
    }

    func node(role: String? = nil, label: String? = nil, identifier: String? = nil) -> Node? {
        nodes.first {
            (role == nil || $0.role == role) && (label == nil || $0.label == label || $0.value == label)
                && (identifier == nil || $0.identifier == identifier)
        }
    }

    func nodes(role: String) -> [Node] { nodes.filter { $0.role == role } }
}

/// Hosts a SwiftUI view in a real (but unseen) window and reads or drives it through accessibility.
@MainActor
final class HostedWindow {
    let window: NSWindow
    let host: NSHostingView<AnyView>
    private static var accessibilityOn = false

    init(_ view: some View, size: NSSize = NSSize(width: 1080, height: 660)) {
        window = NSWindow(contentRect: NSRect(origin: .zero, size: size),
                          styleMask: [.titled, .resizable, .closable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        host = NSHostingView(rootView: AnyView(view))
        window.contentView = host
        window.orderFront(nil)
        if !Self.accessibilityOn {
            // Setting these on our own process marks an accessibility client as present; the calls
            // report an error but have the effect.
            let app = AXUIElementCreateApplication(getpid())
            for key in ["AXManualAccessibility", "AXEnhancedUserInterface"] {
                _ = AXUIElementSetAttributeValue(app, key as CFString, kCFBooleanTrue)
            }
            NSApp.setAccessibilityEnabled(true)
            Self.accessibilityOn = true
        }
    }

    func close() { window.close() }

    /// The view a read or press targets: the sheet the window is showing, if any, else its content.
    private func root(sheet: Bool) -> NSView { sheet ? (window.attachedSheet?.contentView ?? host) : host }

    /// The tree of the sheet the window is presenting, once it has appeared.
    func sheetTree(containing text: String, timeout: TimeInterval = 10) async throws -> AXTree {
        let deadline = Date().addingTimeInterval(timeout)
        var current = AXTree(root(sheet: true))
        while !current.contains(text), Date() < deadline {
            try await Task.sleep(for: .milliseconds(300))
            current = AXTree(root(sheet: true))
        }
        return current
    }

    /// The tree after the run loop has settled. The first read after a change primes SwiftUI's
    /// lazily built nodes, so it reads until the size stops changing.
    func tree(settle: TimeInterval = 0.5) async throws -> AXTree {
        try await Task.sleep(for: .seconds(settle))
        var current = AXTree(host)
        for _ in 0..<6 {
            try await Task.sleep(for: .milliseconds(250))
            let next = AXTree(host)
            let stable = next.nodes.count == current.nodes.count && next.nodes.count > 1
            current = next
            if stable { break }
        }
        return current
    }

    /// Reads the tree until `text` shows up (or the timeout passes), for content that loads
    /// asynchronously.
    func tree(containing text: String, timeout: TimeInterval = 10) async throws -> AXTree {
        let deadline = Date().addingTimeInterval(timeout)
        var current = try await tree(settle: 0.3)
        while !current.contains(text), Date() < deadline {
            try await Task.sleep(for: .milliseconds(300))
            current = AXTree(host)
        }
        return current
    }

    /// Reads the tree until `text` is gone.
    func tree(without text: String, timeout: TimeInterval = 10) async throws -> AXTree {
        let deadline = Date().addingTimeInterval(timeout)
        var current = try await tree(settle: 0.3)
        while current.contains(text), Date() < deadline {
            try await Task.sleep(for: .milliseconds(300))
            current = AXTree(host)
        }
        return current
    }

    /// Presses the first control with this label or identifier. Returns false if there is none.
    @discardableResult
    func press(label: String? = nil, identifier: String? = nil, role: String? = nil, index: Int = 0,
               sheet: Bool = false) async throws -> Bool {
        let matches = AXTree(root(sheet: sheet)).nodes.filter {
            (role == nil || $0.role == role) && (label == nil || $0.label == label || $0.value == label)
                && (identifier == nil || $0.identifier == identifier)
        }
        guard matches.indices.contains(index) else { return false }
        let node = matches[index]
        let element = node.element
        if element.responds(to: NSSelectorFromString("accessibilityPerformPress")) {
            _ = element.perform(NSSelectorFromString("accessibilityPerformPress"))
        } else if element.responds(to: NSSelectorFromString("accessibilityPerformAction:")) {
            _ = element.perform(NSSelectorFromString("accessibilityPerformAction:"), with: "AXPress")
        } else {
            return false
        }
        try await Task.sleep(for: .milliseconds(300))
        return true
    }

    /// Types into a text field: focuses it and inserts through its field editor, so the binding
    /// sees the edit as it would a keystroke.
    @discardableResult
    func type(_ text: String, label: String? = nil, identifier: String? = nil, sheet: Bool = false) async throws -> Bool {
        let tree = AXTree(root(sheet: sheet))
        let field = tree.nodes.first {
            ["AXTextField", "AXTextArea", "AXComboBox"].contains($0.role)
                && (label == nil || $0.label == label) && (identifier == nil || $0.identifier == identifier)
        }
        guard let field else { return false }
        // SwiftUI exposes a text field through its cell.
        let target = (field.element as? NSCell)?.controlView ?? field.element
        if let control = target as? NSTextField {
            guard window.makeFirstResponder(control), let editor = control.currentEditor() else { return false }
            editor.selectAll(nil)
            editor.insertText(text)
        } else if let view = target as? NSTextView {
            guard window.makeFirstResponder(view) else { return false }
            view.selectAll(nil)
            view.insertText(text, replacementRange: view.selectedRange())
        } else {
            let selector = NSSelectorFromString("accessibilitySetValue:forAttribute:")
            guard field.element.responds(to: selector) else { return false }
            _ = field.element.perform(selector, with: text as NSString, with: "AXValue")
        }
        try await Task.sleep(for: .milliseconds(300))
        return true
    }
}
