import AppKit
import Foundation
import SecureAppKit
import WebKit

/// What the bridge needs from the rest of the app.
@MainActor
protocol BridgeHost: AnyObject {
    var client: AppClient? { get }
    func bridgeIdentity() -> [String: Any]?
    func bridgeSignOut()
    func bridgeLive(on: Bool)
    func bridgeOpen(path: String, suggestedName: String?) async -> BridgeRefusal?
    /// Where the page is, for its tab's title and the sidebar.
    func bridgePage(_ state: AppPageState)
}

/// window.webkit.messageHandlers.secureApp (shared/src/bridge.ts). Every message
/// is validated (BridgeValidator) before anything is signed, and only the
/// bundled page's main frame may post: an iframe (an HTML preview, say) never reaches the signer.
@MainActor
final class BridgeHandler: NSObject, WKScriptMessageHandlerWithReply {
    weak var host: BridgeHost?

    init(host: BridgeHost) {
        self.host = host
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage, replyHandler: @escaping @MainActor @Sendable (Any?, String?) -> Void) {
        let origin = message.frameInfo.securityOrigin
        guard message.frameInfo.isMainFrame, origin.protocol == AppBridge.appScheme, origin.host == AppBridge.appHost else {
            Log.bridge.error("bridge message refused, reason: frame_not_allowed")
            replyHandler(Self.refused(.frameNotAllowed), nil)
            return
        }
        let request: BridgeRequest
        switch BridgeValidator.parse(message.body) {
        case .failure(let refusal):
            Log.bridge.notice("bridge message refused, reason: \(refusal.rawValue, privacy: .public)")
            replyHandler(Self.refused(refusal), nil)
            return
        case .success(let r):
            request = r
        }
        guard let host else {
            replyHandler(Self.refused(.notReady), nil)
            return
        }

        switch request {
        case .identity:
            replyHandler(host.bridgeIdentity() ?? Self.refused(.notReady), nil)
        case .signOut:
            host.bridgeSignOut()
            replyHandler(["kind": "ok"], nil)
        case .live(let on):
            host.bridgeLive(on: on)
            replyHandler(["kind": "ok"], nil)
        case .page(let state):
            host.bridgePage(state)
            replyHandler(["kind": "ok"], nil)
        case .open(let path, let name):
            Task { @MainActor in
                if let refusal = await host.bridgeOpen(path: path, suggestedName: name) {
                    replyHandler(Self.refused(refusal), nil)
                } else {
                    replyHandler(["kind": "ok"], nil)
                }
            }
        case .fetch(let http):
            guard let client = host.client else {
                replyHandler(Self.refused(.notReady), nil)
                return
            }
            Task {
                let result = await client.perform(http)
                await MainActor.run {
                    switch result {
                    case .response(let status, let headers, let body):
                        replyHandler(["kind": "fetch", "status": status, "headers": headers, "body": Self.encode(body, contentType: headers["Content-Type"])], nil)
                    case .failed(let reason):
                        replyHandler(["kind": "refused", "reason": reason], nil)
                    }
                }
            }
        }
    }

    static func refused(_ refusal: BridgeRefusal) -> [String: Any] {
        ["kind": "refused", "reason": refusal.rawValue]
    }

    /// Text bodies as text, everything else (PDFs, images, CSV with odd bytes) as base64.
    static func encode(_ body: Data, contentType: String?) -> [String: String] {
        let type = (contentType ?? "").lowercased()
        let textual = type.hasPrefix("text/") || type.contains("json") || type.contains("xml") || type.contains("javascript")
        if textual, let text = String(data: body, encoding: .utf8) {
            return ["encoding": "text", "data": text]
        }
        return ["encoding": "base64", "data": body.base64EncodedString()]
    }
}
