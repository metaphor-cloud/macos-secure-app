import Foundation

/// DCAppAttestService, behind a protocol so enrolment and signing are tested
/// without Apple. The app's implementation is AppAttestDevice.
public protocol Attester: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

/// DCError, reduced to what the app does about it (Apple: retry serverUnavailable
/// later with the same key and the same clientDataHash; on anything else discard the key).
public enum AttestError: Error, Equatable, Sendable {
    case serverUnavailable
    case featureUnsupported
    case invalidKey
    case invalidInput
    case unknown(code: Int)

    public var discardsKey: Bool {
        self != .serverUnavailable
    }

    /// An assertion failed because the key is dead, not because of this request. An assertion
    /// never calls Apple, so an unknown error is the Secure Enclave refusing the key (seen after
    /// a reboot: "unable to sign digest", reported as code 0), and retrying cannot fix it.
    public var keyCannotSign: Bool {
        switch self {
        case .invalidKey, .unknown: true
        case .serverUnavailable, .featureUnsupported, .invalidInput: false
        }
    }

    public var code: String {
        switch self {
        case .serverUnavailable: "server_unavailable"
        case .featureUnsupported: "feature_unsupported"
        case .invalidKey: "invalid_key"
        case .invalidInput: "invalid_input"
        case .unknown(let code): "unknown_\(code)"
        }
    }
}

/// This Mac's App Attest key for one Metaphor ID user. Apple: one key per user
/// per device, never shared between users, and the key id cannot be recovered,
/// so it lives in the Keychain under the user's sub.
public struct AttestKeyRecord: Codable, Equatable, Sendable {
    public var keyId: String
    /// Set once /register accepted it. A key that is generated but not enrolled is reused for the next try.
    public var enrolled: Bool
    public var deviceLabel: String

    public init(keyId: String, enrolled: Bool, deviceLabel: String) {
        self.keyId = keyId
        self.enrolled = enrolled
        self.deviceLabel = deviceLabel
    }
}

public final class AttestKeyStore: @unchecked Sendable {
    private let store: SecureStore

    public init(store: SecureStore) {
        self.store = store
    }

    static func account(for sub: String) -> String {
        "attest-key.\(sub)"
    }

    public func record(for sub: String) -> AttestKeyRecord? {
        do {
            return try store.value(AttestKeyRecord.self, for: Self.account(for: sub))
        } catch {
            Log.attest.error("stored key record unreadable, discarded")
            try? store.remove(Self.account(for: sub))
            return nil
        }
    }

    public func save(_ record: AttestKeyRecord, for sub: String) throws {
        try store.setValue(record, for: Self.account(for: sub))
    }

    public func discard(for sub: String) {
        do { try store.remove(Self.account(for: sub)) } catch { Log.attest.error("stored key record could not be removed") }
    }
}

/// The default device label: the Mac's name, cut to what the Worker takes.
public func cleanDeviceLabel(_ raw: String) -> String? {
    let label = String(raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard !label.isEmpty else { return nil }
    return String(label.prefix(AppContract.deviceLabelMax))
}

/// Backoff for attestKey's serverUnavailable (Apple: exponential backoff, same
/// key, same clientDataHash). Bounded by the enrolment challenge's life: past
/// it, the Worker refuses the challenge anyway, so the next round asks for a
/// new one (and keeps the key).
public struct AttestRetryPolicy: Equatable, Sendable {
    public var initialDelay: TimeInterval = 2
    public var maxDelay: TimeInterval = 60
    /// The enrolment challenge lasts 5 minutes; stop retrying with it well before that.
    public var budget: TimeInterval = 4 * 60

    public init(initialDelay: TimeInterval = 2, maxDelay: TimeInterval = 60, budget: TimeInterval = 4 * 60) {
        self.initialDelay = initialDelay
        self.maxDelay = maxDelay
        self.budget = budget
    }

    /// The wait before retry number `attempt` (0-based), or nil once `elapsed` plus that wait passes the budget.
    public func delay(attempt: Int, elapsed: TimeInterval) -> TimeInterval? {
        let d = min(initialDelay * pow(2, Double(attempt)), maxDelay)
        return elapsed + d > budget ? nil : d
    }
}
