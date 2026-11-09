import AppKit
import SwiftUI
import SecureAppKit

/// Settings for "Let AI apps on this Mac use Secure App": off by
/// default, the secret, and the listener's life. The listener runs only while
/// this is on; what it answers is gated on the app being signed in, enrolled
/// and unlocked.
@MainActor
final class MCPController: ObservableObject {
    static let enabledKey = "secureapp.mcp.enabled"

    @Published private(set) var enabled: Bool
    @Published private(set) var secret: String?
    @Published private(set) var error: String?

    private let secrets: MCPSecretStore
    private var server: LocalMCPServer?
    private let handler: AppMCPHandler
    private let port = LocalMCPServer.defaultPort

    var url: String { "http://127.0.0.1:\(port)/mcp" }

    /// For Claude Code. Shown with the secret hidden; copied in full.
    func claudeCodeCommand(revealed: Bool) -> String {
        let token = revealed ? (secret ?? "") : "••••••••"
        return "claude mcp add --transport http secure-app \(url) --header \"Authorization: Bearer \(token)\""
    }

    init(store: SecureStore, perform: @escaping AppMCPHandler.Perform, isReady: @escaping AppMCPHandler.IsReady) {
        enabled = UserDefaults.standard.bool(forKey: Self.enabledKey)
        secrets = MCPSecretStore(store: store)
        handler = AppMCPHandler(perform: perform, confirm: { await MCPConfirmationPrompt.shared.ask($0) }, isReady: isReady)
        if enabled { startServer() }
    }

    func setEnabled(_ on: Bool) {
        guard on != enabled else { return }
        enabled = on
        UserDefaults.standard.set(on, forKey: Self.enabledKey)
        if on { startServer() } else { stopServer() }
    }

    func regenerate() {
        secret = secrets.regenerate()
        Log.mcp.info("mcp secret regenerated")
    }

    private func startServer() {
        secret = secrets.current()
        guard secret != nil else {
            error = "Couldn't save the secret to the Keychain."
            return
        }
        let secrets = secrets
        let server = LocalMCPServer(port: port, handler: handler, secret: { secrets.current() })
        server.onState = { [weak self] _, message in
            Task { @MainActor in self?.error = message }
        }
        self.server = server
        error = nil
        server.start()
    }

    private func stopServer() {
        server?.stop()
        server = nil
        error = nil
        secret = nil
    }
}

/// The person's yes or no on a write, in front of everything else. One question at
/// a time, and the default button is the safe one, so a stray Return declines.
@MainActor
final class MCPConfirmationPrompt {
    static let shared = MCPConfirmationPrompt()
    private let gate = SerialGate()

    func ask(_ confirmation: MCPConfirmation) async -> Bool {
        await gate.acquire()
        let answer = present(confirmation)
        await gate.release()
        return answer
    }

    private func present(_ confirmation: MCPConfirmation) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = confirmation.destructive ? .critical : .warning
        alert.messageText = confirmation.title
        alert.informativeText = "An AI app on this Mac asked Secure App to do this."
        alert.accessoryView = Self.detailView(confirmation.detail)
        // First button is the default: declining.
        alert.addButton(withTitle: "Don't allow")
        let allow = alert.addButton(withTitle: "Allow")
        allow.hasDestructiveAction = confirmation.destructive
        NSApp.activate(ignoringOtherApps: true)
        let window = alert.window
        window.level = .modalPanel
        return alert.runModal() == .alertSecondButtonReturn
    }

    private static func detailView(_ text: String) -> NSView {
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 420, height: 160))
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        let view = NSTextView(frame: scroll.bounds)
        view.isEditable = false
        view.isSelectable = true
        view.font = .systemFont(ofSize: NSFont.systemFontSize)
        view.string = text
        view.autoresizingMask = [.width]
        view.textContainerInset = NSSize(width: 6, height: 6)
        scroll.documentView = view
        return scroll
    }
}
