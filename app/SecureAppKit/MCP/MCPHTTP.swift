import CryptoKit
import Foundation
import Security

/// The HTTP side of the local MCP server, without sockets: parsing a
/// request head and deciding whether to answer it. LocalMCPServer (Network.framework)
/// feeds bytes in and writes the answer out.

public struct MCPHTTPHead: Equatable, Sendable {
    public var method: String
    public var target: String
    /// Lower-cased names.
    public var headers: [String: String]

    public var contentLength: Int? { headers["content-length"].flatMap { Int($0) } }

    /// nil until the blank line that ends the head has arrived. `consumed` is the head's length in bytes.
    public static func parse(_ data: Data) -> (head: MCPHTTPHead, consumed: Int)? {
        guard let end = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        guard let text = String(data: data[data.startIndex..<end.lowerBound], encoding: .utf8) else { return nil }
        var lines = text.components(separatedBy: "\r\n")
        let parts = lines.removeFirst().split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard parts.count == 3, parts[2].hasPrefix("HTTP/1.") else { return nil }
        var headers: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let name = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            // A repeated Authorization, Host or Content-Length is how smuggling starts.
            if headers[name] != nil { headers[name] = "\u{0}duplicate"; continue }
            headers[name] = value
        }
        return (MCPHTTPHead(method: parts[0], target: parts[1], headers: headers), data.distance(from: data.startIndex, to: end.upperBound))
    }
}

public enum MCPHTTPRefusal: String, Equatable, Sendable {
    case badRequest = "bad_request"
    case methodNotAllowed = "method_not_allowed"
    case notFound = "not_found"
    case originPresent = "origin_present"
    case hostNotAllowed = "host_not_allowed"
    case unauthorised = "unauthorised"
    case lengthRequired = "length_required"
    case bodyTooLarge = "body_too_large"

    public var status: Int {
        switch self {
        case .badRequest: 400
        case .methodNotAllowed: 405
        case .notFound: 404
        case .originPresent, .hostNotAllowed: 403
        case .unauthorised: 401
        case .lengthRequired: 411
        case .bodyTooLarge: 413
        }
    }
}

public enum MCPHTTPGuard {
    public static let path = "/mcp"
    public static let maxHeadBytes = 16 * 1024
    public static let maxBodyBytes = 256 * 1024

    /// Why this request is refused, or nil to read its body and answer it.
    /// Order matters: the cheap refusals first, the secret before anything is read.
    public static func check(_ head: MCPHTTPHead, port: UInt16, secret: String) -> MCPHTTPRefusal? {
        guard head.method == "POST" else { return .methodNotAllowed }
        guard head.target == path else { return .notFound }
        // A browser page sends Origin; nothing legitimate on this Mac does.
        if head.headers["origin"] != nil { return .originPresent }
        // DNS rebinding: the name the client asked for must be this machine's loopback.
        guard let host = head.headers["host"]?.lowercased(), host == "127.0.0.1:\(port)" || host == "localhost:\(port)" else { return .hostNotAllowed }
        guard bearerMatches(head.headers["authorization"], secret: secret) else { return .unauthorised }
        if head.headers["transfer-encoding"] != nil { return .lengthRequired }
        if head.headers["content-length"] == "\u{0}duplicate" { return .badRequest }
        guard let length = head.contentLength, length >= 0 else { return .lengthRequired }
        guard length <= maxBodyBytes else { return .bodyTooLarge }
        return nil
    }

    static func bearerMatches(_ header: String?, secret: String) -> Bool {
        guard let header, header.count > 7, header.prefix(7).lowercased() == "bearer " else { return false }
        return constantTimeEqual(String(header.dropFirst(7)), secret)
    }

    /// Compares SHA-256 digests of both, so neither the length nor the first differing byte shows in the time taken.
    public static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(SHA256.hash(data: Data(a.utf8)))
        let y = Array(SHA256.hash(data: Data(b.utf8)))
        var difference: UInt8 = 0
        for i in 0..<x.count { difference |= x[i] ^ y[i] }
        return difference == 0
    }
}

/// The per-install secret AI apps send as a bearer token. Random, kept in the
/// Keychain through SecureStore, replaced on demand.
public final class MCPSecretStore: @unchecked Sendable {
    public static let account = "mcp-secret"
    private let store: SecureStore
    private let lock = NSLock()

    public init(store: SecureStore) {
        self.store = store
    }

    /// The current secret, made on first use.
    public func current() -> String? {
        lock.withLock {
            if let data = try? store.data(for: Self.account), let text = String(data: data, encoding: .utf8), !text.isEmpty { return text }
            return Self.make().flatMap { store(secret: $0) }
        }
    }

    /// A new secret; the old one stops working at once.
    public func regenerate() -> String? {
        lock.withLock { Self.make().flatMap { store(secret: $0) } }
    }

    private func store(secret: String) -> String? {
        do {
            try store.set(Data(secret.utf8), for: Self.account)
            return secret
        } catch {
            Log.mcp.error("mcp secret not saved")
            return nil
        }
    }

    static func make() -> String? {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            Log.mcp.error("mcp secret not made, reason: no_randomness")
            return nil
        }
        let base64 = Data(bytes).base64EncodedString()
        return "secureapp_" + base64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
