import Foundation

/// The SPA to shell bridge, mirroring shared/src/bridge.ts. The page never
/// reaches the network: every call arrives here, is validated, and only then
/// signed. A page compromised by injected content can therefore reach nothing
/// the API does not already gate, and never the native-only enrolment,
/// session and live paths.
public enum AppBridge {
    public static let handlerName = "secureApp"
    public static let receiver = "__secureAppNative"
    public static let nativeScheme = "secureapp-native"
    /// The scheme the bundled SPA is served from, as secureapp://app/.
    public static let appScheme = "secureapp"
    public static let appHost = "app"
    public static let requestHeaders = ["Content-Type", "Accept"]
    public static let responseHeaders = ["Content-Type", "Content-Disposition", "Retry-After"]
    public static let maxBodyBytes = 25 * 1024 * 1024
    public static let methods: Set<String> = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    /// What a bridged path starts with, and the parts of it that stay native-only.
    public static let apiPrefix = "/api/"
    public static let nativeOnlyPrefixes = ["/api/attest/"]
    public static let nativeOnlyPaths = ["/api/attest", "/api/live"]

    /// Whether a frame may be navigated to a signed native load. Only a frame the
    /// bundled SPA points there: an HTML preview (srcdoc) redirecting itself, by
    /// meta refresh or script, would make a signed request with this Mac's key.
    /// Its CSP covers loads, not navigations, so this does.
    public static func allowsNativeFrameNavigation(from source: URL?) -> Bool {
        guard let source else { return false }
        return source.scheme == appScheme && source.host == appHost
    }
}

/// isBridgedPath in bridge.ts, rule for rule: under /api/, no climbing out, and
/// never the enrolment, session or live paths.
public func isBridgedPath(_ path: String) -> Bool {
    guard path.hasPrefix(AppBridge.apiPrefix) else { return false }
    let pathname = path.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
    if pathname.contains("..") || pathname.contains("//") || pathname.range(of: "%2e|%2f", options: [.regularExpression, .caseInsensitive]) != nil {
        return false
    }
    if AppBridge.nativeOnlyPaths.contains(pathname) { return false }
    return !AppBridge.nativeOnlyPrefixes.contains { pathname.hasPrefix($0) }
}

private let canonicalTarget = try! NSRegularExpression(
    pattern: #"^/[A-Za-z0-9\-._~!$&'()*+,;=:@%/]*(\?[A-Za-z0-9\-._~!$&()*+,;=:@%/?]+)?$"#
)

/// Whether the Worker will see exactly these bytes as url.pathname + url.search,
/// which is what it hashes into clientData. The WHATWG URL parser rewrites some
/// targets (it drops an empty "?", removes "." segments, encodes a quote in the
/// query, treats a backslash as a slash), and a rewritten target would fail the
/// signature, so the bridge refuses them up front with a reason the page can see.
public func isCanonicalRequestTarget(_ path: String) -> Bool {
    guard matches(canonicalTarget, path) else { return false }
    let pathname = path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? path
    // "." and ".." segments are resolved by the parser.
    if pathname.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }) { return false }
    // A % must start a valid escape.
    let scalars = Array(path.unicodeScalars)
    for (i, c) in scalars.enumerated() where c == "%" {
        guard i + 2 < scalars.count, scalars[i + 1].properties.isASCIIHexDigit, scalars[i + 2].properties.isASCIIHexDigit else { return false }
    }
    return true
}

/// A reason code for a refused bridge request. Never request content.
public enum BridgeRefusal: String, Error, Sendable {
    case malformed = "malformed"
    case unknownKind = "unknown_kind"
    case pathNotAllowed = "path_not_allowed"
    case pathNotCanonical = "path_not_canonical"
    case methodNotAllowed = "method_not_allowed"
    case bodyTooLarge = "body_too_large"
    case bodyMalformed = "body_malformed"
    case bodyNotAllowed = "body_not_allowed"
    case frameNotAllowed = "frame_not_allowed"
    case notReady = "not_ready"
    /// An "open" whose signed fetch did not come back with the file.
    case openFailed = "open_failed"
    /// A "page" message whose title, badge, route or nav list is out of bounds.
    case pageNotAllowed = "page_not_allowed"
}

/// An API call the shell will sign and send.
public struct AppHTTPRequest: Equatable, Sendable {
    public var method: String
    public var pathAndQuery: String
    public var headers: [String: String]
    public var body: Data?

    public init(method: String, pathAndQuery: String, headers: [String: String] = [:], body: Data? = nil) {
        self.method = method.uppercased()
        self.pathAndQuery = pathAndQuery
        self.headers = headers
        self.body = body
    }
}

public enum BridgeRequest: Equatable, Sendable {
    case fetch(AppHTTPRequest)
    case identity
    case signOut
    case live(on: Bool)
    case open(path: String, suggestedName: String?)
    /// Where the tab is, for its title and the sidebar.
    case page(AppPageState)
}

public enum BridgeValidator {
    /// Validates a message the page posted. `body` is what WebKit hands over: an NSDictionary of plist types.
    public static func parse(_ body: Any) -> Result<BridgeRequest, BridgeRefusal> {
        guard let dict = body as? [String: Any], let kind = dict["kind"] as? String else { return .failure(.malformed) }
        switch kind {
        case "identity": return .success(.identity)
        case "signOut": return .success(.signOut)
        case "live":
            guard let on = dict["on"] as? Bool else { return .failure(.malformed) }
            return .success(.live(on: on))
        case "open":
            guard let path = dict["path"] as? String else { return .failure(.malformed) }
            if let refusal = checkPath(path) { return .failure(refusal) }
            let name = (dict["suggestedName"] as? String).flatMap(sanitiseFileName)
            return .success(.open(path: path, suggestedName: name))
        case "fetch":
            return parseFetch(dict).map(BridgeRequest.fetch)
        case "page":
            return AppNav.parsePage(dict).map(BridgeRequest.page)
        default:
            return .failure(.unknownKind)
        }
    }

    public static func checkPath(_ path: String) -> BridgeRefusal? {
        if !isBridgedPath(path) { return .pathNotAllowed }
        if !isCanonicalRequestTarget(path) { return .pathNotCanonical }
        return nil
    }

    static func parseFetch(_ dict: [String: Any]) -> Result<AppHTTPRequest, BridgeRefusal> {
        guard let rawMethod = dict["method"] as? String, let path = dict["path"] as? String else { return .failure(.malformed) }
        let method = rawMethod.uppercased()
        guard AppBridge.methods.contains(method) else { return .failure(.methodNotAllowed) }
        if let refusal = checkPath(path) { return .failure(refusal) }

        var headers: [String: String] = [:]
        if let raw = dict["headers"] {
            guard let given = raw as? [String: Any] else { return .failure(.malformed) }
            headers = filterRequestHeaders(given)
        }

        var body: Data?
        if let raw = dict["body"] {
            switch decodeBody(raw) {
            case .success(let data): body = data
            case .failure(let refusal): return .failure(refusal)
            }
            if method == "GET" { return .failure(.bodyNotAllowed) }
        }
        return .success(AppHTTPRequest(method: method, pathAndQuery: path, headers: headers, body: body))
    }

    /// Only the allow-listed headers survive, under their canonical names. Anything else
    /// (Authorization, Cookie, the X-App-* headers) is dropped, never forwarded.
    public static func filterRequestHeaders(_ given: [String: Any]) -> [String: String] {
        var out: [String: String] = [:]
        for (name, value) in given {
            guard let canonical = AppBridge.requestHeaders.first(where: { $0.caseInsensitiveCompare(name) == .orderedSame }),
                  let v = value as? String, !v.contains("\r"), !v.contains("\n"), v.utf8.count <= 1024 else { continue }
            out[canonical] = v
        }
        return out
    }

    /// The response headers the page gets back, under their canonical names.
    public static func filterResponseHeaders(_ given: [AnyHashable: Any]) -> [String: String] {
        var out: [String: String] = [:]
        for (name, value) in given {
            guard let n = name as? String,
                  let canonical = AppBridge.responseHeaders.first(where: { $0.caseInsensitiveCompare(n) == .orderedSame }) else { continue }
            out[canonical] = "\(value)"
        }
        return out
    }

    static func decodeBody(_ raw: Any) -> Result<Data, BridgeRefusal> {
        guard let b = raw as? [String: Any], let encoding = b["encoding"] as? String, let data = b["data"] as? String else {
            return .failure(.bodyMalformed)
        }
        let max = AppBridge.maxBodyBytes
        switch encoding {
        case "text":
            guard data.utf8.count <= max else { return .failure(.bodyTooLarge) }
            return .success(Data(data.utf8))
        case "base64":
            // Checked before decoding, so an oversized string is never expanded in memory.
            guard data.utf8.count <= (max / 3 + 1) * 4 else { return .failure(.bodyTooLarge) }
            guard let decoded = Data(base64Encoded: data) else { return .failure(.bodyMalformed) }
            guard decoded.count <= max else { return .failure(.bodyTooLarge) }
            return .success(decoded)
        default:
            return .failure(.bodyMalformed)
        }
    }

    /// A file name the save panel can offer: no path separators or control characters.
    public static func sanitiseFileName(_ name: String) -> String? {
        let cleaned = String(name.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) && $0 != "/" && $0 != ":" && $0 != "\\" })
            .trimmingCharacters(in: .whitespaces)
        let trimmed = cleaned.hasPrefix(".") ? String(cleaned.drop(while: { $0 == "." })) : cleaned
        guard !trimmed.isEmpty else { return nil }
        return String(trimmed.prefix(200))
    }
}
