import AppKit
import SecureAppKit
import WebKit

/// One tab's web view: the bundled SPA on secureapp://app, the
/// bridge, signed direct loads on secureapp-native:, and nothing else. No remote
/// navigation: links to other sites open in the default browser, and a link
/// into the app asked for in a new tab or window opens in a new tab.
@MainActor
final class WebController: NSObject, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
    let webView: WKWebView
    private let bridge: BridgeHandler
    private weak var host: (BridgeHost & AnyObject)?
    private var urlObservation: NSKeyValueObservation?
    var onRouteChange: ((String) -> Void)?
    /// A route to open in a new tab: ⌘-click, middle-click, or the link menu's Open in New Tab.
    var onOpenInNewTab: ((String) -> Void)?

    static let startURL = URL(string: "\(AppBridge.appScheme)://\(AppBridge.appHost)/index.html")!

    init(host: BridgeHost, client: AppClient, bundleRoot: URL) {
        self.host = host
        bridge = BridgeHandler(host: host)
        let config = WKWebViewConfiguration()
        config.setURLSchemeHandler(AppSchemeHandler(root: bundleRoot), forURLScheme: AppBridge.appScheme)
        config.setURLSchemeHandler(NativeLoadHandler(client: client), forURLScheme: AppBridge.nativeScheme)
        // Nothing the page stores outlives the window: no cookies, no local storage on disk.
        config.websiteDataStore = .nonPersistent()
        config.limitsNavigationsToAppBoundDomains = true
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        config.preferences.isFraudulentWebsiteWarningEnabled = false
        config.userContentController.addScriptMessageHandler(bridge, contentWorld: .page, name: AppBridge.handlerName)
        webView = AppWebView(frame: .zero, configuration: config)
        super.init()
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.allowsBackForwardNavigationGestures = true
        #if DEBUG
        webView.isInspectable = true
        #endif
        urlObservation = webView.observe(\.url, options: [.new]) { [weak self] view, _ in
            guard let fragment = view.url?.fragment, AppNav.isRoute(fragment) else { return }
            MainActor.assumeIsolated { self?.onRouteChange?(fragment) }
        }
    }

    func teardown() {
        webView.configuration.userContentController.removeScriptMessageHandler(forName: AppBridge.handlerName, contentWorld: .page)
        webView.stopLoading()
        urlObservation = nil
    }

    /// Loads the SPA at a hash route (restored from the last session), or its start page.
    func load(route: String?) {
        var url = Self.startURL
        if let route, AppNav.isRoute(route),
           let routed = URL(string: "\(Self.startURL.absoluteString)#\(route)") {
            url = routed
        }
        webView.load(URLRequest(url: url))
    }

    func reload() {
        webView.reload()
    }

    /// Moves the running SPA to a hash route (a tapped notification), without reloading it.
    func navigate(route: String) {
        guard AppNav.isRoute(route) else { return }
        webView.callAsyncJavaScript("window.location.hash = route;", arguments: ["route": route], in: nil, in: .page) { [weak self] result in
            if case .failure = result { self?.load(route: route) }
        }
    }

    /// window.__secureAppNative.receive(event), in the page's own world.
    func push(_ event: [String: Any]) {
        webView.callAsyncJavaScript(
            "const r = window[name]; if (r && typeof r.receive === 'function') r.receive(event);",
            arguments: ["name": AppBridge.receiver, "event": event],
            in: nil,
            in: .page
        ) { result in
            if case .failure = result { Log.web.notice("event not delivered to page") }
        }
    }

    // MARK: Navigation

    private static func isBundle(_ url: URL) -> Bool {
        url.scheme == AppBridge.appScheme && url.host == AppBridge.appHost
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, preferences: WKWebpagePreferences) async -> (WKNavigationActionPolicy, WKWebpagePreferences) {
        guard let url = action.request.url else { return (.cancel, preferences) }
        let disposition = AppLinkDisposition.decide(
            url: url,
            commandKey: action.modifierFlags.contains(.command),
            middleButton: action.buttonNumber == 2,
            wantsNewWindow: action.targetFrame == nil
        )
        if case .newTab(let route) = disposition {
            Log.web.info("link opened in a new tab")
            onOpenInNewTab?(route)
            return (.cancel, preferences)
        }
        let mainFrame = action.targetFrame?.isMainFrame ?? true
        if action.shouldPerformDownload { return (.download, preferences) }
        switch url.scheme {
        case AppBridge.appScheme where Self.isBundle(url):
            return (.allow, preferences)
        case "about" where url.absoluteString == "about:blank" || url.absoluteString == "about:srcdoc":
            return (.allow, preferences)
        case "blob", "data":
            return (mainFrame ? .download : .allow, preferences)
        case AppBridge.nativeScheme:
            if !mainFrame {
                guard AppBridge.allowsNativeFrameNavigation(from: action.sourceFrame.request.url) else {
                    Log.web.notice("navigation refused, reason: native_from_frame")
                    return (.cancel, preferences)
                }
                return (.allow, preferences)
            }
            // A link to a signed file: fetch it and hand it to the system, never navigate away from the SPA.
            if let path = NativeLoadHandler.pathAndQuery(of: url) { _ = await host?.bridgeOpen(path: path, suggestedName: nil) }
            return (.cancel, preferences)
        case "https", "http", "mailto", "tel":
            if action.navigationType == .linkActivated || action.targetFrame == nil {
                openExternally(url)
            } else {
                Log.web.notice("navigation refused, reason: remote_navigation")
            }
            return (.cancel, preferences)
        default:
            Log.web.notice("navigation refused, reason: scheme_not_allowed")
            return (.cancel, preferences)
        }
    }

    func webView(_ webView: WKWebView, decidePolicyFor response: WKNavigationResponse) async -> WKNavigationResponsePolicy {
        response.canShowMIMEType ? .allow : .download
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) {
        download.delegate = self
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        Log.web.error("web content process ended, reloading")
        webView.reload()
    }

    private func openExternally(_ url: URL) {
        guard ["https", "http", "mailto", "tel"].contains(url.scheme ?? "") else { return }
        Log.web.info("opened a link in the default browser")
        NSWorkspace.shared.open(url)
    }

    // MARK: Windows and panels

    /// target=_blank, window.open and the link menu's Open in New Tab: a page of the app opens in a new
    /// tab, other sites go to the browser, signed files to the system. Never a web view WebKit made.
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        guard let url = action.request.url else { return nil }
        if let route = AppLinkDisposition.appRoute(of: url) {
            Log.web.info("link opened in a new tab")
            onOpenInNewTab?(route)
        } else if url.scheme == AppBridge.nativeScheme, let path = NativeLoadHandler.pathAndQuery(of: url) {
            Task { _ = await host?.bridgeOpen(path: path, suggestedName: nil) }
        } else if url.scheme == "blob" || url.scheme == "data" {
            webView.startDownload(using: URLRequest(url: url)) { $0.delegate = self }
        } else {
            openExternally(url)
        }
        return nil
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo) async {
        let alert = NSAlert()
        alert.messageText = message
        alert.addButton(withTitle: "OK")
        _ = await present(alert)
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo) async -> Bool {
        let alert = NSAlert()
        alert.messageText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        return await present(alert) == .alertFirstButtonReturn
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String, defaultText: String?, initiatedByFrame frame: WKFrameInfo) async -> String? {
        let alert = NSAlert()
        alert.messageText = prompt
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        field.stringValue = defaultText ?? ""
        alert.accessoryView = field
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        return await present(alert) == .alertFirstButtonReturn ? field.stringValue : nil
    }

    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters, initiatedByFrame frame: WKFrameInfo) async -> [URL]? {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.canChooseFiles = true
        guard let window = webView.window else { return panel.runModal() == .OK ? panel.urls : nil }
        let response = await panel.beginSheetModal(for: window)
        return response == .OK ? panel.urls : nil
    }

    private func present(_ alert: NSAlert) async -> NSApplication.ModalResponse {
        guard let window = webView.window else { return alert.runModal() }
        return await alert.beginSheetModal(for: window)
    }

    // MARK: Downloads (blob: links, such as a file the page builds itself)

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse, suggestedFilename: String) async -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = BridgeValidator.sanitiseFileName(suggestedFilename) ?? "download"
        panel.canCreateDirectories = true
        let result: NSApplication.ModalResponse
        if let window = webView.window { result = await panel.beginSheetModal(for: window) } else { result = panel.runModal() }
        guard result == .OK, let url = panel.url else { return nil }
        // WKDownload will not overwrite; the panel already asked.
        try? FileManager.default.removeItem(at: url)
        return url
    }

    func downloadDidFinish(_ download: WKDownload) {
        Log.web.info("download finished")
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        Log.web.error("download failed: \((error as NSError).code, privacy: .public)")
    }
}

/// The tab's WKWebView, with the link menu saying what its new-window item does here.
final class AppWebView: WKWebView {
    override func willOpenMenu(_ menu: NSMenu, with event: NSEvent) {
        for item in menu.items {
            switch item.identifier?.rawValue {
            case "WKMenuItemIdentifierOpenLinkInNewWindow":
                item.title = Copy.Menu.openInNewTab
            case "WKMenuItemIdentifierOpenImageInNewWindow", "WKMenuItemIdentifierOpenFrameInNewWindow", "WKMenuItemIdentifierOpenMediaInNewWindow":
                // A new window of an image or frame isn't something the shell makes.
                item.isHidden = true
            default:
                break
            }
        }
        super.willOpenMenu(menu, with: event)
    }
}
