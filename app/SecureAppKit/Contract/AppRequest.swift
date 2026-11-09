import CryptoKit
import Foundation

/// The signed request, mirroring shared/src/request.ts exactly. ContractDriftTests
/// reads that file and fails if a value here no longer appears in it, and
/// GoldenVectorTests checks the signed string byte for byte against
/// shared/vectors/request.json.
public enum AppHeader {
    public static let app = "X-App-Id"
    public static let key = "X-App-Key"
    public static let time = "X-App-Time"
    public static let nonce = "X-App-Nonce"
    public static let challenge = "X-App-Challenge"
    public static let assertion = "X-App-Assertion"
}

public enum AppContract {
    public static let clientDataVersion = "secure-app-v1"
    /// How far a request's timestamp may sit from the Worker's clock.
    public static let maxSkewMs: Int64 = 120 * 1000
    public static let attestChallengePath = "/api/attest/challenge"
    public static let attestRegisterPath = "/api/attest/register"
    public static let attestSessionPath = "/api/attest/session"
    /// What a key with no current session challenge signs over, on the session path only.
    public static let sessionBootstrap = "bootstrap"
    public static let deviceLabelMax = 64
    public static let platform = "macos"
    /// The live socket, gated like any other path under /api/.
    public static let livePath = "/api/live"
    /// The body of the gate's uniform refusal (the Worker's REFUSAL_MESSAGE).
    /// A 403 with any other body is a handler's own answer (a permission check, say)
    /// and is handed to the page, never treated as an attestation failure.
    public static let gateRefusalMessage = "This needs the app on an enrolled device."
}

public struct AppRequestParts: Equatable, Sendable {
    public var appId: String
    public var keyId: String
    public var method: String
    /// Path and query exactly as sent, e.g. /api/notes?q=x.
    public var pathAndQuery: String
    /// Lower-case hex SHA-256 of the body bytes; of the empty string when none.
    public var bodySha256: String
    /// Lower-case hex SHA-256 of the bearer token's UTF-8 bytes.
    public var tokenSha256: String
    public var time: Int64
    public var nonce: String
    public var challenge: String

    public init(appId: String, keyId: String, method: String, pathAndQuery: String, bodySha256: String, tokenSha256: String, time: Int64, nonce: String, challenge: String) {
        self.appId = appId
        self.keyId = keyId
        self.method = method
        self.pathAndQuery = pathAndQuery
        self.bodySha256 = bodySha256
        self.tokenSha256 = tokenSha256
        self.time = time
        self.nonce = nonce
        self.challenge = challenge
    }
}

/// The exact string the assertion signs (clientData in request.ts).
public func appClientData(_ p: AppRequestParts) -> String {
    [
        AppContract.clientDataVersion,
        p.appId,
        p.keyId,
        p.method.uppercased(),
        p.pathAndQuery,
        p.bodySha256,
        p.tokenSha256,
        String(p.time),
        p.nonce,
        p.challenge,
    ].joined(separator: "\n")
}

public func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

public func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

public func sha256Hex(_ string: String) -> String {
    sha256Hex(Data(string.utf8))
}

/// 16 to 64 characters of [A-Za-z0-9_-]: 24 random bytes, base64url, 32 characters.
public func makeNonce() -> String {
    var bytes = [UInt8](repeating: 0, count: 24)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    precondition(status == errSecSuccess, "no randomness")
    return Data(bytes).base64URLEncodedString()
}

public let noncePattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9_-]{16,64}$")
public let challengePattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9_-]{43}$")

public func matches(_ regex: NSRegularExpression, _ s: String) -> Bool {
    regex.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
}

public extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncoded s: String) {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        self.init(base64Encoded: b)
    }
}
