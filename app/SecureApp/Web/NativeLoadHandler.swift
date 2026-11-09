import Foundation
import SecureAppKit
import WebKit

/// secureapp-native:///api/...: the loads the page cannot route through the
/// bridge's fetch (iframes, images, media). Fetched and signed natively, with the
/// same path rules as the bridge, GET only.
final class NativeLoadHandler: NSObject, WKURLSchemeHandler {
    private let client: AppClient
    private var stopped = Set<ObjectIdentifier>()
    private let lock = NSLock()

    init(client: AppClient) {
        self.client = client
    }

    /// The API path and query in a secureapp-native URL, exactly as the page wrote it.
    static func pathAndQuery(of url: URL) -> String? {
        let prefix = "\(AppBridge.nativeScheme)://"
        let s = url.absoluteString
        guard s.hasPrefix(prefix) else { return nil }
        var rest = String(s.dropFirst(prefix.count))
        if let hash = rest.firstIndex(of: "#") { rest = String(rest[..<hash]) }
        return rest
    }

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        let id = ObjectIdentifier(task)
        guard let url = task.request.url, let path = Self.pathAndQuery(of: url) else {
            fail(task, reason: "malformed")
            return
        }
        guard (task.request.httpMethod ?? "GET").uppercased() == "GET" else {
            fail(task, reason: BridgeRefusal.methodNotAllowed.rawValue)
            return
        }
        if let refusal = BridgeValidator.checkPath(path) {
            Log.bridge.notice("direct load refused, reason: \(refusal.rawValue, privacy: .public)")
            fail(task, reason: refusal.rawValue)
            return
        }
        Task {
            let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: path, headers: ["Accept": "*/*"]))
            await MainActor.run {
                guard self.lock.withLock({ self.stopped.remove(id) == nil }) else { return }
                switch result {
                case .response(let status, let headers, let body):
                    var out = headers
                    out["Content-Length"] = String(body.count)
                    out["Cache-Control"] = "no-store"
                    // Attachments are opened through the "open" request, never rendered from a direct load.
                    out.removeValue(forKey: "Content-Disposition")
                    task.didReceive(HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: out)!)
                    task.didReceive(body)
                    task.didFinish()
                case .failed(let reason):
                    self.fail(task, reason: reason)
                }
            }
        }
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {
        _ = lock.withLock { stopped.insert(ObjectIdentifier(task)) }
    }

    private func fail(_ task: WKURLSchemeTask, reason: String) {
        task.didFailWithError(NSError(domain: "com.example.secureapp.native-load", code: 1, userInfo: [NSLocalizedDescriptionKey: reason]))
    }
}
