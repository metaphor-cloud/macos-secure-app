import AppKit
import Foundation
import SecureAppKit

/// One window tab's page: its own web view and bridge, sharing
/// the app's signed client, live socket and lock through AppModel. The page
/// tells the tab where it is ("page"), which titles the tab and moves the
/// window's sidebar.
@MainActor
final class AppTab: ObservableObject, BridgeHost {
    @Published private(set) var page: AppPageState?
    /// Set once, in init: the web view's bridge needs the tab as its host.
    private(set) var web: WebController!
    private weak var model: AppModel?

    init(model: AppModel, client: AppClient, bundleRoot: URL) {
        self.model = model
        web = WebController(host: self, client: client, bundleRoot: bundleRoot)
        web.onRouteChange = { route in UserDefaults.standard.set(route, forKey: AppModel.routeKey) }
        web.onOpenInNewTab = { [weak model] route in model?.openTab(route: route) }
    }

    /// The tab's title: the page's own, or Secure App until it has said.
    var title: String { page?.title ?? "Secure App" }

    func load(route: String?) { web.load(route: route) }
    func navigate(route: String) { web.navigate(route: route) }
    func push(_ event: [String: Any]) { web.push(event) }
    func reload() { web.reload() }
    func teardown() { web.teardown() }

    // MARK: BridgeHost

    var client: AppClient? { model?.client }

    func bridgeIdentity() -> [String: Any]? { model?.bridgeIdentity() }

    func bridgeSignOut() { model?.bridgeSignOut() }

    func bridgeLive(on: Bool) { model?.setLive(on: on, for: self) }

    func bridgeOpen(path: String, suggestedName: String?) async -> BridgeRefusal? {
        guard let model else { return .notReady }
        return await model.open(path: path, suggestedName: suggestedName, window: web.webView.window)
    }

    func bridgePage(_ state: AppPageState) {
        page = state
        model?.pageChanged(state)
    }
}
