import Foundation
import SecureAppKit
import UniformTypeIdentifiers
import WebKit

/// Serves the bundled SPA (Resources/WebApp) at secureapp://app/.
/// The page is never loaded from the network: the files in the signed app are the
/// only code that runs in the web view.
final class AppSchemeHandler: NSObject, WKURLSchemeHandler {
    let root: URL

    init(root: URL) {
        self.root = root.standardizedFileURL
    }

    static func bundledRoot() -> URL? {
        guard let url = Bundle.main.resourceURL?.appendingPathComponent("WebApp", isDirectory: true),
              FileManager.default.fileExists(atPath: url.appendingPathComponent("index.html").path)
        else { return nil }
        return url
    }

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        guard let url = task.request.url, url.host == AppBridge.appHost, let file = file(for: url.path) else {
            Log.web.notice("bundle request refused, reason: not_in_bundle")
            respond(task, status: 404, type: "text/plain", data: Data("Not found".utf8))
            return
        }
        do {
            let data = try Data(contentsOf: file)
            respond(task, status: 200, type: Self.mimeType(for: file), data: data)
        } catch {
            Log.web.error("bundle file unreadable: \(file.lastPathComponent, privacy: .public)")
            respond(task, status: 404, type: "text/plain", data: Data("Not found".utf8))
        }
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {}

    /// The file for a request path, only if it is inside the bundle folder.
    func file(for path: String) -> URL? {
        let relative = path.isEmpty || path == "/" ? "index.html" : String(path.drop(while: { $0 == "/" }))
        let candidate = root.appendingPathComponent(relative).standardizedFileURL
        guard candidate.path.hasPrefix(root.path + "/") else { return nil }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory), !isDirectory.boolValue else { return nil }
        return candidate
    }

    static func mimeType(for file: URL) -> String {
        switch file.pathExtension.lowercased() {
        case "html": return "text/html"
        case "js", "mjs": return "text/javascript"
        case "css": return "text/css"
        case "json", "map": return "application/json"
        case "svg": return "image/svg+xml"
        case "woff2": return "font/woff2"
        case "woff": return "font/woff"
        case "wasm": return "application/wasm"
        default: return UTType(filenameExtension: file.pathExtension)?.preferredMIMEType ?? "application/octet-stream"
        }
    }

    private func respond(_ task: WKURLSchemeTask, status: Int, type: String, data: Data) {
        var headers = ["Content-Type": type.hasPrefix("text/") ? "\(type); charset=utf-8" : type, "Content-Length": String(data.count), "Cache-Control": "no-store"]
        headers["X-Content-Type-Options"] = "nosniff"
        let response = HTTPURLResponse(url: task.request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        task.didReceive(response)
        task.didReceive(data)
        task.didFinish()
    }
}
