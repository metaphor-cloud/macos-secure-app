import AppKit
import AuthenticationServices
import SecureAppKit

/// The browser half of Metaphor ID sign-in: ASWebAuthenticationSession,
/// ephemeral, so no Metaphor ID cookie outlives a sign-out and each sign-in
/// starts at Metaphor ID afresh, so enrolment can see the org's SSO.
@MainActor
final class WebAuthenticator: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var session: ASWebAuthenticationSession?

    func signIn(oidc: OIDCClient, config: AppConfig, forceLogin: Bool) async throws -> StoredTokens {
        let request = try await oidc.authorizationRequest(forceLogin: forceLogin)
        let callback = try await present(request.url, scheme: config.redirectURI.scheme ?? "secureapp-mac")
        let code = try OIDCClient.code(from: callback, for: request)
        return try await oidc.exchange(code: code, for: request)
    }

    private func present(_ url: URL, scheme: String) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(url: url, callback: .customScheme(scheme)) { callback, error in
                if let callback {
                    continuation.resume(returning: callback)
                } else if let error = error as? ASWebAuthenticationSessionError, error.code == .canceledLogin {
                    continuation.resume(throwing: AuthError.cancelled)
                } else {
                    Log.auth.error("web sign-in failed: \(String(describing: error.map { ($0 as NSError).code }), privacy: .public)")
                    continuation.resume(throwing: AuthError.refused(reason: "web_auth_failed"))
                }
            }
            session.prefersEphemeralWebBrowserSession = true
            session.presentationContextProvider = self
            self.session = session
            if !session.start() {
                continuation.resume(throwing: AuthError.refused(reason: "web_auth_not_started"))
            }
        }
    }

    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            NSApp.keyWindow ?? NSApp.windows.first ?? ASPresentationAnchor()
        }
    }
}
