import AppKit
import SwiftUI
import SecureAppKit

/// Which screen the window shows. Every attestation state
/// has its own screen; none of them is ever shown as "signed out", and none has
/// a way round attestation.
enum Phase: Equatable {
    case starting
    case misconfigured
    case unsupported
    case fullSecurityNeeded
    case signedOut(notice: String?)
    case signingIn
    case nameThisMac
    case enrolling(EnrolStage)
    case appleUnavailable
    case ssoRequired
    case rateLimited
    case enrolRefused
    case unreachable
    case failed(String)
    case reenrol
    case clockWrong
    case ready
}

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var phase: Phase = .starting
    @Published private(set) var identity: AppIdentity?
    @Published private(set) var record: AttestKeyRecord?
    @Published var proposedLabel: String = AppModel.defaultLabel()
    /// The sidebar's pages and the badge count, from the last page that said.
    @Published private(set) var nav: [AppNavGroup] = []
    @Published private(set) var badge = 0
    /// Bumped each time every tab's web view is torn down, so each window makes a new one.
    @Published private(set) var webGeneration = 0

    let lock = LockController()
    /// The local MCP server for AI apps on this Mac; off unless turned on in Settings.
    private(set) var mcp: MCPController!
    let config: AppConfig?
    private(set) var client: AppClient?
    private var tokens: TokenManager?
    private var oidc: OIDCClient?
    private var keys: AttestKeyStore?
    private let attester = AppAttestDevice()
    private let authenticator = WebAuthenticator()
    private var live: LiveSocket?
    private var restoredRoute: String?
    private var started = false
    private var pageLocked = false
    /// Every open tab, each with its own web view. One live socket serves them all.
    private var tabs: [ObjectIdentifier: AppTab] = [:]
    private var liveWanted: Set<ObjectIdentifier> = []
    /// The tab in the key window: the menu's Reload and a tapped notification act on it.
    private(set) weak var activeTab: AppTab?
    /// Opens a window for a tab request; set by the first window, which has SwiftUI's openWindow.
    var openWindow: ((TabRequest) -> Void)?
    /// The window a new tab joins, from the moment it is asked for until its window appears.
    var pendingTabParent: NSWindow?

    static let keychainService = "com.example.secureapp"
    static let routeKey = "secureapp.lastRoute"

    init() {
        config = AppConfig.fromBundle()
        if let config {
            let store = KeychainStore(service: Self.keychainService)
            let transport = URLSessionTransport()
            let oidc = OIDCClient(config: config, transport: transport)
            let tokens = TokenManager(store: store, oidc: oidc)
            let keys = AttestKeyStore(store: store)
            let client = AppClient(config: config, transport: transport, attester: attester, tokens: tokens, keys: keys)
            self.oidc = oidc
            self.tokens = tokens
            self.keys = keys
            self.client = client
            client.onEvent { [weak self] event in
                Task { @MainActor in self?.handle(event) }
            }
        }
        restoredRoute = UserDefaults.standard.string(forKey: Self.routeKey)
        // Every MCP call goes through the signing client, and only while signed in, enrolled and unlocked.
        let mcpClient = client
        mcp = MCPController(
            store: KeychainStore(service: Self.keychainService),
            perform: { request in await mcpClient?.perform(request) ?? .failed(reason: "not_configured") },
            isReady: { [weak self] in await self?.isReadyForMCP() ?? false }
        )
        // The page drops its data on "locked" and refetches on "unlocked".
        lock.onChange = { [weak self] state in
            guard let self, self.phase == .ready, !state.authenticating else { return }
            guard state.locked != self.pageLocked else { return }
            self.pageLocked = state.locked
            self.pushToTabs(["type": "session", "state": state.locked ? "locked" : "unlocked"])
        }
    }

    /// Signed in, enrolled, showing the app and not locked: the only time an AI app's call is answered.
    func isReadyForMCP() -> Bool {
        phase == .ready && identity != nil && record?.enrolled == true && !lock.state.locked
    }

    static func defaultLabel() -> String {
        cleanDeviceLabel(Host.current().localizedName ?? "") ?? "Mac"
    }

    // MARK: Start

    func start() {
        guard !started else { return }
        started = true
        Task { await resume() }
    }

    /// From whatever is in the Keychain to the right screen.
    private func resume() async {
        guard let tokens, let keys, let client else {
            Log.app.fault("app configuration missing from Info.plist")
            phase = .misconfigured
            return
        }
        // No bypass: a Mac that cannot attest never gets as far as signing in.
        guard attester.isSupported else {
            Log.app.error("app attest not supported, hard stop")
            phase = .unsupported
            return
        }
        guard let stored = await tokens.load(), let idToken = stored.idToken, let who = AppIdentity(idToken: idToken) else {
            phase = .signedOut(notice: nil)
            return
        }
        identity = who
        if let existing = keys.record(for: who.sub), existing.enrolled {
            record = existing
            await client.use(sub: who.sub, keyId: existing.keyId)
            showApp()
        } else {
            record = keys.record(for: who.sub)
            proposedLabel = record?.deviceLabel ?? Self.defaultLabel()
            phase = .nameThisMac
        }
    }

    // MARK: Sign in and out

    func signIn(forceLogin: Bool = false) {
        guard let oidc, let tokens, let config else { return }
        phase = .signingIn
        Task {
            do {
                let next = try await authenticator.signIn(oidc: oidc, config: config, forceLogin: forceLogin)
                try await tokens.adopt(next)
                Log.auth.info("signed in")
                await resume()
            } catch AuthError.cancelled {
                phase = .signedOut(notice: nil)
            } catch AuthError.unreachable {
                phase = .signedOut(notice: Copy.SignIn.unreachable)
            } catch {
                Log.auth.error("sign-in failed")
                phase = .signedOut(notice: Copy.SignIn.failed)
            }
        }
    }

    /// `forgetPush` deletes this Mac's push token first, with a signed request, so it needs the
    /// session still there: false when the session has already ended.
    func signOut(notice: String? = nil, forgetPush: Bool = true) {
        Log.auth.info("signed out")
        pushToTabs(["type": "session", "state": "signedOut"])
        tearDownWeb()
        badge = 0
        NSApp.dockTile.badgeLabel = nil
        lock.reset()
        identity = nil
        record = nil
        Task {
            if forgetPush { await PushNotifications.shared.signOut() }
            await tokens?.signOut()
            await client?.use(sub: nil, keyId: nil)
        }
        phase = .signedOut(notice: notice)
    }

    // MARK: Enrolment

    func enrol() {
        guard let client, let who = identity else { return }
        let label = proposedLabel
        guard cleanDeviceLabel(label) != nil else { return }
        phase = .enrolling(.challenge)
        Task {
            let outcome = await client.enrol(sub: who.sub, deviceLabel: label) { stage in
                Task { @MainActor [weak self] in
                    if case .enrolling = self?.phase { self?.phase = .enrolling(stage) }
                }
            }
            switch outcome {
            case .enrolled(let r):
                record = r
                showApp()
            case .unsupported: phase = .unsupported
            case .fullSecurityNeeded: phase = .fullSecurityNeeded
            case .appleUnavailable: phase = .appleUnavailable
            case .ssoRequired: phase = .ssoRequired
            case .signIn: signOut(notice: Copy.SignIn.sessionEnded, forgetPush: false)
            case .rateLimited: phase = .rateLimited
            case .refused: phase = .enrolRefused
            case .unreachable: phase = .unreachable
            case .failed(let reason): phase = .failed(reason)
            }
        }
    }

    /// The revoked or lost key: forget it here and add this Mac again.
    func addAgain() {
        guard let who = identity else { return }
        keys?.discard(for: who.sub)
        record = nil
        proposedLabel = Self.defaultLabel()
        Task { await client?.use(sub: who.sub, keyId: nil) }
        phase = .nameThisMac
    }

    /// After a sign-in without the org's SSO: a fresh one, so it can be used.
    func signInWithSso() {
        tearDownWeb()
        Task { await tokens?.signOut() }
        signIn(forceLogin: true)
    }

    func retry() {
        if record?.enrolled == true {
            showApp()
        } else if identity != nil {
            enrol()
        } else {
            phase = .signedOut(notice: nil)
        }
    }

    // MARK: App

    /// Signed in on an enrolled key: the windows show their tabs, and the live socket and push are set up.
    private func showApp() {
        guard let client, AppSchemeHandler.bundledRoot() != nil else {
            Log.app.fault("web bundle missing from the app")
            phase = .failed("bundle_missing")
            return
        }
        tearDownWeb()
        pageLocked = false
        let push = PushNotifications.shared
        live = LiveSocket(client: client) { [weak self] event in
            self?.pushToTabs(event)
        }
        push.openRoute = { [weak self] route in self?.showRoute(route) }
        push.enable(client: client)
        phase = .ready
    }

    /// A new tab's page, for a window that has just appeared or come back to ready. The first
    /// tab after launch opens a tapped notification's page, else the last page.
    func makeTab(route: String?) -> AppTab? {
        guard phase == .ready, let client, let root = AppSchemeHandler.bundledRoot() else { return nil }
        let tab = AppTab(model: self, client: client, bundleRoot: root)
        tabs[ObjectIdentifier(tab)] = tab
        let first = PushNotifications.shared.takePendingRoute() ?? route ?? restoredRoute
        restoredRoute = nil
        tab.load(route: first)
        if activeTab == nil { activeTab = tab }
        Log.web.info("tab opened")
        return tab
    }

    /// A window closed, or left ready: its tab's web view goes, and its share of the live socket.
    func closeTab(_ tab: AppTab) {
        let id = ObjectIdentifier(tab)
        guard tabs.removeValue(forKey: id) != nil else { return }
        tab.teardown()
        setLive(on: false, for: tab)
        if activeTab === tab { activeTab = tabs.values.first }
    }

    func tabBecameActive(_ tab: AppTab) {
        activeTab = tab
    }

    /// Opens a route in a new tab of the key window (⌘T, ⌘-click, Open in New Tab).
    func openTab(route: String?) {
        guard let openWindow else {
            Log.app.error("new tab not opened, reason: no_window_opener")
            return
        }
        pendingTabParent = NSApp.keyWindow ?? NSApp.mainWindow
        openWindow(TabRequest(route: route))
    }

    /// A tapped notification: the key window's tab moves to it, or a new tab opens.
    private func showRoute(_ route: String) {
        if let tab = activeTab {
            tab.navigate(route: route)
        } else {
            openTab(route: route)
        }
    }

    func reload() {
        guard phase == .ready else { return }
        activeTab?.reload()
    }

    /// The live socket stays up while any tab wants it.
    func setLive(on: Bool, for tab: AppTab) {
        let id = ObjectIdentifier(tab)
        if on { liveWanted.insert(id) } else { liveWanted.remove(id) }
        live?.set(on: !liveWanted.isEmpty)
    }

    func pageChanged(_ state: AppPageState) {
        if nav != state.nav { nav = state.nav }
        if badge != state.badge {
            badge = state.badge
            NSApp.dockTile.badgeLabel = AppNav.badgeText(state.badge)
        }
    }

    private func pushToTabs(_ event: [String: Any]) {
        for tab in tabs.values { tab.push(event) }
    }

    private func tearDownWeb() {
        PushNotifications.shared.openRoute = nil
        live?.stop()
        live = nil
        liveWanted.removeAll()
        for tab in tabs.values { tab.teardown() }
        tabs.removeAll()
        activeTab = nil
        webGeneration += 1
    }

    private func handle(_ event: AppClientEvent) {
        switch event {
        case .needsSignIn:
            guard phase != .signingIn else { return }
            signOut(notice: Copy.SignIn.sessionEnded, forgetPush: false)
        case .needsReenrol:
            tearDownWeb()
            phase = .reenrol
        case .clockWrong:
            tearDownWeb()
            phase = .clockWrong
        }
    }

    // MARK: For every tab's bridge

    func bridgeIdentity() -> [String: Any]? {
        guard let identity, let record, record.enrolled else { return nil }
        return ["kind": "identity", "email": identity.email, "name": identity.name, "sub": identity.sub, "deviceLabel": record.deviceLabel, "keyId": record.keyId]
    }

    func bridgeSignOut() {
        signOut()
    }

    func open(path: String, suggestedName: String?, window: NSWindow?) async -> BridgeRefusal? {
        if let refusal = BridgeValidator.checkPath(path) { return refusal }
        guard let client else { return .notReady }
        let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: path, headers: ["Accept": "*/*"]))
        guard case .response(let status, let headers, let body) = result, (200..<300).contains(status) else {
            Log.web.notice("open failed")
            return .openFailed
        }
        Downloads.deliver(body: body, headers: headers, path: path, suggestedName: suggestedName, window: window)
        return nil
    }
}

/// What a new window opens. The id makes every request a new window:
/// SwiftUI brings an open window forward for a value it already shows.
struct TabRequest: Codable, Hashable {
    var id = UUID()
    var route: String?
}
