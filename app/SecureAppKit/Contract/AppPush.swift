import Foundation

/// Push notifications on the Mac. The Worker sends to APNs directly with the
/// token this Mac registers against its App Attest key, through the signed
/// client like any other request. The paths mirror the Worker's push routes;
/// ContractDriftTests checks them against shared/src/request.ts.
public enum AppPush {
    public static let tokenPath = "/api/push/token"
    public static let testPath = "/api/push/test"
}

/// Which APNs host a token works on. A development-signed build gets sandbox tokens.
public enum APNsEnvironment: String, Sendable {
    case production
    case development

    /// This build's: development in Debug, production otherwise.
    public static var current: APNsEnvironment {
        #if DEBUG
        return .development
        #else
        return .production
        #endif
    }
}

/// The device token as the Worker stores it: lower-case hex, two characters a byte.
public func apnsTokenHex(_ token: Data) -> String {
    token.map { String(format: "%02x", $0) }.joined()
}

/// The signed POST that registers this Mac's APNs token.
public func pushRegisterRequest(token: Data, environment: APNsEnvironment) -> AppHTTPRequest? {
    guard !token.isEmpty else { return nil }
    let body: [String: String] = ["token": apnsTokenHex(token), "environment": environment.rawValue]
    guard let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]) else { return nil }
    return AppHTTPRequest(method: "POST", pathAndQuery: AppPush.tokenPath, headers: ["Content-Type": "application/json", "Accept": "application/json"], body: data)
}

/// The signed DELETE that forgets it, on sign-out.
public func pushUnregisterRequest() -> AppHTTPRequest {
    AppHTTPRequest(method: "DELETE", pathAndQuery: AppPush.tokenPath, headers: ["Accept": "application/json"])
}

/// The page a tapped notification is about, as a hash route for the SPA. The
/// Worker sends the route in the payload's top-level "path", as the SPA writes
/// it ("#/notes"). Anything that is not a route is ignored.
public func appRoute(forPushPath path: String) -> String? {
    let route = AppNav.route(from: path)
    return AppNav.isRoute(route) ? route : nil
}

/// The route in a notification's userInfo (the payload's top-level "path"), or nil.
public func appRoute(fromPushUserInfo userInfo: [AnyHashable: Any]) -> String? {
    guard let path = userInfo["path"] as? String else { return nil }
    return appRoute(forPushPath: path)
}
