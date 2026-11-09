import Foundation

/// What to do with a response to a signed request.
///
/// The gate answers every refusal with the same 403, by design, and logs the
/// real reason. The recovery: refresh the session challenge and
/// retry once; then refresh the token and retry once; then enrol again (a
/// reinstall loses the key, and a revoked key stays refused). Two extra rules:
///
/// - Only the gate's own refusal (its exact body) starts recovery. A handler's
///   own 403 (a permission check) goes straight back to the page. An attestation
///   failure is never read as a session expiry, and a permission answer is
///   never read as an attestation failure.
/// - A refusal whose Date header is more than the Worker's skew limit from this
///   Mac's clock is the clock, not the key: say so instead of re-enrolling.
public enum RecoveryAction: Equatable, Sendable {
    /// Hand the response to the page.
    case deliver
    case refreshSessionAndRetry
    case refreshTokenAndRetry
    /// The key is not accepted any more: show the "add this Mac again" screen.
    case reenrol
    /// The token is not accepted any more: show sign-in.
    case signIn
    /// This Mac's clock is too far out for any signed request to pass.
    case clockWrong
}

public struct ForbiddenRecovery: Equatable, Sendable {
    public private(set) var sessionRefreshed = false
    public private(set) var tokenRefreshed = false

    public init() {}

    public static func isGateRefusal(status: Int, body: Data) -> Bool {
        guard status == 403,
              let json = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any],
              let error = json["error"] as? String
        else { return false }
        return error == AppContract.gateRefusalMessage
    }

    /// Seconds between the Worker's Date header and this Mac's clock, if the header is there.
    public static func clockSkew(serverDate: String?, now: Date) -> TimeInterval? {
        guard let serverDate, let date = httpDateFormatter.date(from: serverDate) else { return nil }
        return now.timeIntervalSince(date)
    }

    static func clockIsOut(serverDate: String?, now: Date) -> Bool {
        guard let skew = clockSkew(serverDate: serverDate, now: now) else { return false }
        // Date has whole seconds; allow for that and for the time in flight.
        return abs(skew) * 1000 > Double(AppContract.maxSkewMs) - 5000
    }

    /// The next step after a response to a signed request.
    public mutating func next(status: Int, body: Data, serverDate: String?, now: Date) -> RecoveryAction {
        if status == 401 {
            // A handler's own "Not authenticated" (the gate is off or reporting): the token.
            if tokenRefreshed { return .signIn }
            tokenRefreshed = true
            return .refreshTokenAndRetry
        }
        guard Self.isGateRefusal(status: status, body: body) else { return .deliver }
        if Self.clockIsOut(serverDate: serverDate, now: now) { return .clockWrong }
        if !sessionRefreshed {
            sessionRefreshed = true
            return .refreshSessionAndRetry
        }
        if !tokenRefreshed {
            tokenRefreshed = true
            return .refreshTokenAndRetry
        }
        return .reenrol
    }

    /// The signed session request itself was refused: the token next, then enrolment.
    public mutating func sessionRefused(serverDate: String?, now: Date) -> RecoveryAction {
        sessionRefreshed = true
        if Self.clockIsOut(serverDate: serverDate, now: now) { return .clockWrong }
        if !tokenRefreshed {
            tokenRefreshed = true
            return .refreshTokenAndRetry
        }
        return .reenrol
    }
}

let httpDateFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "GMT")
    f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    return f
}()
