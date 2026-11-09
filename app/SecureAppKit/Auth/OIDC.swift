import CryptoKit
import Foundation

/// Metaphor ID sign-in: authorisation code with PKCE and an ID token. The
/// browser half (ASWebAuthenticationSession) is in the app target.
public enum OIDC {
    public static let scopes = ["openid", "profile", "email", "groups", "offline_access"]
    /// Refresh this long before the access token runs out, so a request never carries one about to expire.
    public static let expiryMargin: TimeInterval = 60
}

public struct StoredTokens: Codable, Equatable, Sendable {
    public var accessToken: String
    public var refreshToken: String?
    public var idToken: String?
    public var expiresAt: Date?

    public init(accessToken: String, refreshToken: String?, idToken: String?, expiresAt: Date?) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.expiresAt = expiresAt
    }

    public func isFresh(now: Date) -> Bool {
        guard let expiresAt else { return true }
        return expiresAt.timeIntervalSince(now) > OIDC.expiryMargin
    }
}

/// Who is signed in, from the ID token's claims. Display only: the Worker checks the token itself.
public struct AppIdentity: Equatable, Sendable {
    public var sub: String
    public var email: String
    public var name: String

    public init(sub: String, email: String, name: String) {
        self.sub = sub
        self.email = email
        self.name = name
    }

    public init?(idToken: String) {
        guard let claims = decodeJWTPayload(idToken), let sub = claims["sub"] as? String, !sub.isEmpty else { return nil }
        let email = claims["email"] as? String ?? ""
        let name = (claims["name"] as? String) ?? (claims["given_name"] as? String) ?? email
        self.init(sub: sub, email: email, name: name)
    }
}

/// A JWT's payload, unverified. Only for reading our own ID token's claims.
public func decodeJWTPayload(_ jwt: String) -> [String: Any]? {
    let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3, let data = Data(base64URLEncoded: String(parts[1])) else { return nil }
    return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
}

public struct PKCE: Sendable {
    public let verifier: String
    public let challenge: String

    public init(verifier: String) {
        self.verifier = verifier
        self.challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
    }

    public static func make() -> PKCE {
        PKCE(verifier: randomURLSafe(bytes: 32))
    }
}

public func randomURLSafe(bytes count: Int) -> String {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    precondition(status == errSecSuccess, "no randomness")
    return Data(bytes).base64URLEncodedString()
}

public struct OIDCDiscovery: Decodable, Sendable {
    public let issuer: String
    public let authorization_endpoint: URL
    public let token_endpoint: URL
    public let end_session_endpoint: URL?
}

public enum AuthError: Error, Equatable, Sendable {
    /// There is no session: sign in.
    case signedOut
    /// The browser sign-in was cancelled.
    case cancelled
    /// Metaphor ID answered something we cannot use; `reason` is a code.
    case refused(reason: String)
    /// Metaphor ID could not be reached.
    case unreachable
}

/// One sign-in attempt: what the authorise URL was built with, checked on the way back.
public struct AuthorizationRequest: Sendable {
    public let url: URL
    public let state: String
    public let nonce: String
    public let pkce: PKCE
}

public final class OIDCClient: @unchecked Sendable {
    private let config: AppConfig
    private let transport: HTTPTransport
    private let now: @Sendable () -> Date
    private var cached: OIDCDiscovery?
    private let lock = NSLock()

    public init(config: AppConfig, transport: HTTPTransport, now: @escaping @Sendable () -> Date = { Date() }) {
        self.config = config
        self.transport = transport
        self.now = now
    }

    public func discovery() async throws -> OIDCDiscovery {
        if let hit = lock.withLock({ cached }) { return hit }
        let url = config.issuer.appendingPathComponent(".well-known/openid-configuration")
        let (data, response) = try await sendOrUnreachable(URLRequest(url: url))
        guard response.statusCode == 200, let doc = try? JSONDecoder().decode(OIDCDiscovery.self, from: data) else {
            Log.auth.error("oidc discovery failed, status: \(response.statusCode, privacy: .public)")
            throw AuthError.refused(reason: "discovery_failed")
        }
        lock.withLock { cached = doc }
        return doc
    }

    /// `forceLogin` asks Metaphor ID for a fresh sign-in, so the org's SSO can be used (enrolment needs it).
    public func authorizationRequest(forceLogin: Bool) async throws -> AuthorizationRequest {
        let doc = try await discovery()
        let pkce = PKCE.make()
        let state = randomURLSafe(bytes: 16)
        let nonce = randomURLSafe(bytes: 16)
        var parts = URLComponents(url: doc.authorization_endpoint, resolvingAgainstBaseURL: false)!
        var items = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "redirect_uri", value: config.redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: OIDC.scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: pkce.challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]
        if forceLogin { items.append(URLQueryItem(name: "prompt", value: "login")) }
        parts.queryItems = (parts.queryItems ?? []) + items
        return AuthorizationRequest(url: parts.url!, state: state, nonce: nonce, pkce: pkce)
    }

    /// The code from Metaphor ID's redirect, after checking it answers this request.
    public static func code(from callback: URL, for request: AuthorizationRequest) throws -> String {
        let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func item(_ name: String) -> String? { items.first(where: { $0.name == name })?.value }
        if let error = item("error") {
            Log.auth.notice("sign-in refused by metaphor id, error: \(error, privacy: .public)")
            switch error {
            case "access_denied": throw AuthError.refused(reason: "access_denied")
            default: throw AuthError.refused(reason: "authorize_error")
            }
        }
        guard item("state") == request.state else {
            Log.auth.error("sign-in callback refused, reason: state_mismatch")
            throw AuthError.refused(reason: "state_mismatch")
        }
        guard let code = item("code"), !code.isEmpty else { throw AuthError.refused(reason: "code_missing") }
        return code
    }

    public func exchange(code: String, for request: AuthorizationRequest) async throws -> StoredTokens {
        let tokens = try await tokenRequest([
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirectURI.absoluteString,
            "client_id": config.clientId,
            "code_verifier": request.pkce.verifier,
        ], previous: nil)
        guard let idToken = tokens.idToken, let claims = decodeJWTPayload(idToken) else {
            throw AuthError.refused(reason: "id_token_missing")
        }
        let doc = try await discovery()
        let aud = claims["aud"]
        let audOk = (aud as? String) == config.clientId || ((aud as? [String])?.contains(config.clientId) ?? false)
        guard claims["nonce"] as? String == request.nonce, claims["iss"] as? String == doc.issuer, audOk else {
            Log.auth.error("sign-in refused, reason: id_token_mismatch")
            throw AuthError.refused(reason: "id_token_mismatch")
        }
        return tokens
    }

    /// New tokens from the refresh token, or nil when Metaphor ID says the session is over.
    public func refresh(_ current: StoredTokens) async throws -> StoredTokens? {
        guard let refreshToken = current.refreshToken else {
            Log.auth.notice("token refresh not possible, reason: no_refresh_token")
            return nil
        }
        do {
            return try await tokenRequest([
                "grant_type": "refresh_token",
                "refresh_token": refreshToken,
                "client_id": config.clientId,
            ], previous: current)
        } catch AuthError.refused(let reason) {
            Log.auth.notice("token refresh refused, reason: \(reason, privacy: .public)")
            return nil
        }
    }

    private func tokenRequest(_ form: [String: String], previous: StoredTokens?) async throws -> StoredTokens {
        let doc = try await discovery()
        var request = URLRequest(url: doc.token_endpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = formEncode(form).data(using: .utf8)
        let (data, response) = try await sendOrUnreachable(request)
        guard response.statusCode == 200 else {
            let error = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["error"] as? String ?? "http_\(response.statusCode)"
            if response.statusCode >= 500 { throw AuthError.unreachable }
            throw AuthError.refused(reason: error)
        }
        guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let access = json["access_token"] as? String, !access.isEmpty
        else { throw AuthError.refused(reason: "token_response_malformed") }
        let expiresIn = (json["expires_in"] as? NSNumber)?.doubleValue
        return StoredTokens(
            accessToken: access,
            // A refresh may not rotate the refresh token, or send a new ID token: keep the ones we had.
            refreshToken: json["refresh_token"] as? String ?? previous?.refreshToken,
            idToken: json["id_token"] as? String ?? previous?.idToken,
            expiresAt: expiresIn.map { now().addingTimeInterval($0) }
        )
    }

    private func sendOrUnreachable(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        do {
            return try await transport.send(request)
        } catch {
            Log.auth.error("metaphor id unreachable: \(String(describing: type(of: error)), privacy: .public)")
            throw AuthError.unreachable
        }
    }
}

func formEncode(_ form: [String: String]) -> String {
    var allowed = CharacterSet.alphanumerics
    allowed.insert(charactersIn: "-._~")
    return form.keys.sorted().map { key in
        "\(key.addingPercentEncoding(withAllowedCharacters: allowed)!)=\(form[key]!.addingPercentEncoding(withAllowedCharacters: allowed)!)"
    }.joined(separator: "&")
}

/// The source of the bearer token for every request.
public protocol TokenSource: Sendable {
    /// A current access token, refreshed first if it is about to run out. Throws AuthError.signedOut when there is no session.
    func accessToken() async throws -> String
    /// A new access token, whatever the old one's expiry. Throws AuthError.signedOut when the session is over.
    func forceRefresh() async throws -> String
    /// The ID token from the latest sign-in or refresh, for enrolment's SSO and MFA evidence.
    func idToken() async -> String?
}

/// The tokens, in the Keychain, refreshed one at a time.
public actor TokenManager: TokenSource {
    public static let account = "tokens"

    private let store: SecureStore
    private let oidc: OIDCClient
    private let now: @Sendable () -> Date
    private var tokens: StoredTokens?
    private var refreshing: Task<StoredTokens?, Error>?

    public init(store: SecureStore, oidc: OIDCClient, now: @escaping @Sendable () -> Date = { Date() }) {
        self.store = store
        self.oidc = oidc
        self.now = now
    }

    /// Reads the saved session, if any.
    public func load() -> StoredTokens? {
        do {
            tokens = try store.value(StoredTokens.self, for: Self.account)
        } catch {
            Log.auth.error("stored tokens unreadable, cleared")
            try? store.remove(Self.account)
            tokens = nil
        }
        return tokens
    }

    public func adopt(_ next: StoredTokens) throws {
        try store.setValue(next, for: Self.account)
        tokens = next
    }

    public func signOut() {
        refreshing?.cancel()
        refreshing = nil
        tokens = nil
        do { try store.remove(Self.account) } catch { Log.auth.error("stored tokens could not be removed") }
    }

    public var current: StoredTokens? { tokens }

    public func idToken() async -> String? { tokens?.idToken }

    public func accessToken() async throws -> String {
        guard let tokens else { throw AuthError.signedOut }
        if tokens.isFresh(now: now()) { return tokens.accessToken }
        return try await forceRefresh()
    }

    /// One refresh at a time: requests queued behind a refresh must not spend the refresh token twice.
    public func forceRefresh() async throws -> String {
        guard let current = tokens else { throw AuthError.signedOut }
        let task: Task<StoredTokens?, Error>
        if let running = refreshing {
            task = running
        } else {
            let oidc = self.oidc
            task = Task { try await oidc.refresh(current) }
            refreshing = task
        }
        defer { if refreshing == task { refreshing = nil } }
        guard let next = try await task.value else {
            Log.auth.notice("session ended, signing out")
            signOut()
            throw AuthError.signedOut
        }
        try adopt(next)
        return next.accessToken
    }
}
