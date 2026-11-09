import Foundation

/// The Mac app lock.
///
/// The lock comes on when the Mac's screen locks, the displays sleep, the
/// session switches to another user, or from Lock Now. Another app in front
/// does nothing: the person at the keyboard is still the one who unlocked the
/// Mac. Once on, only Touch ID or the Mac's password takes it off; coming back
/// to the window never does. The locked flag is persisted, so quitting while
/// locked and launching again is still locked.
///
/// Pure: storage and the prompt are passed in, so it is unit tested.
public protocol LockStorage: AnyObject {
    func string(forKey key: String) -> String?
    func set(_ value: String, forKey key: String)
    func remove(_ key: String)
}

extension UserDefaults: LockStorage {
    public func set(_ value: String, forKey key: String) {
        set(value as Any, forKey: key)
    }

    public func remove(_ key: String) {
        removeObject(forKey: key)
    }
}

public final class InMemoryLockStorage: LockStorage {
    public var values: [String: String] = [:]
    public init() {}
    public func string(forKey key: String) -> String? { values[key] }
    public func set(_ value: String, forKey key: String) { values[key] = value }
    public func remove(_ key: String) { values.removeValue(forKey: key) }
}

public struct LockState: Equatable, Sendable {
    public var locked: Bool
    public var authenticating: Bool

    public init(locked: Bool, authenticating: Bool) {
        self.locked = locked
        self.authenticating = authenticating
    }
}

/// Why the lock came on, for the log.
public enum LockReason: String, Sendable {
    case screenLocked = "screen_locked"
    case screenSlept = "screen_slept"
    case sessionSwitched = "session_switched"
    case menu
}

@MainActor
public final class AppLockManager {
    public static let lockedKey = "secureapp.locked"

    public typealias Prompt = () async -> (success: Bool, error: String?)

    public private(set) var state = LockState(locked: false, authenticating: false) {
        didSet { if state != oldValue { onChange?(state) } }
    }
    public var onChange: ((LockState) -> Void)?

    private let storage: LockStorage
    private let prompt: Prompt

    public init(storage: LockStorage, prompt: @escaping Prompt) {
        self.storage = storage
        self.prompt = prompt
        // Decided before the first frame, so protected content never shows before the cover goes up.
        if storage.string(forKey: Self.lockedKey) != nil {
            state.locked = true
            Log.lock.info("app locked on launch, still locked when it quit")
        }
    }

    /// Cover the window until Touch ID or the password unlocks it.
    public func lock(_ reason: LockReason) {
        storage.set("1", forKey: Self.lockedKey)
        guard !state.locked else { return }
        state.locked = true
        Log.lock.info("app locked, reason: \(reason.rawValue, privacy: .public)")
    }

    /// Signed out: nothing to protect, nothing to remember.
    public func reset() {
        storage.remove(Self.lockedKey)
        state = LockState(locked: false, authenticating: false)
    }

    public func authenticate() async {
        guard state.locked, !state.authenticating else { return }
        state.authenticating = true
        let result = await prompt()
        if result.success {
            storage.remove(Self.lockedKey)
            state = LockState(locked: false, authenticating: false)
            Log.lock.info("biometric unlock succeeded")
        } else {
            state.authenticating = false
            Log.lock.notice("biometric unlock failed, reason: \(result.error ?? "unknown", privacy: .public)")
        }
    }
}
