import Foundation

/// The network, behind a protocol so the signer and the recovery flow are tested without it.
public protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct TransportError: Error, Sendable {
    public let message: String
}

/// URLSession with no cookies, no cache and no credential storage: the bearer
/// token and the assertion are the only credentials a request carries.
public final class URLSessionTransport: HTTPTransport, @unchecked Sendable {
    public let session: URLSession

    public init() {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.urlCache = nil
        config.urlCredentialStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 60
        session = URLSession(configuration: config)
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw TransportError(message: "not_http") }
        return (data, http)
    }
}

/// What the app is configured against, from Info.plist (Config/Shared.xcconfig).
public struct AppConfig: Equatable, Sendable {
    public var apiBase: URL
    public var issuer: URL
    public var clientId: String
    public var redirectURI: URL
    /// Team ID, a period, and the signing identifier: X-App-Id.
    public var appId: String

    public init(apiBase: URL, issuer: URL, clientId: String, redirectURI: URL, appId: String) {
        self.apiBase = apiBase
        self.issuer = issuer
        self.clientId = clientId
        self.redirectURI = redirectURI
        self.appId = appId
    }

    public static func fromBundle(_ bundle: Bundle = .main) -> AppConfig? {
        func url(_ key: String) -> URL? { (bundle.object(forInfoDictionaryKey: key) as? String).flatMap(URL.init(string:)) }
        guard let apiBase = url("AppAPIBase"), let issuer = url("AppOIDCIssuer"), let redirect = url("AppOIDCRedirectURI"),
              let clientId = bundle.object(forInfoDictionaryKey: "AppOIDCClientID") as? String, !clientId.isEmpty,
              let appId = bundle.object(forInfoDictionaryKey: "AppID") as? String, !appId.isEmpty
        else { return nil }
        return AppConfig(apiBase: apiBase, issuer: issuer, clientId: clientId, redirectURI: redirect, appId: appId)
    }

    /// The URL for an API path. Built from the string so the target is sent exactly as signed.
    public func url(for pathAndQuery: String) -> URL? {
        var base = apiBase.absoluteString
        while base.hasSuffix("/") { base.removeLast() }
        return URL(string: base + pathAndQuery)
    }
}
