import AppKit
import LocalAuthentication
import SecureAppKit

/// Wires AppLockManager to the Mac: the screen locking, the
/// displays sleeping and the session switching out lock the app. Another app
/// in front does not. Coming back to a locked window waits for Unlock to be
/// clicked before asking for Touch ID: the prompt takes focus, so it never
/// appears on its own.
@MainActor
final class LockController: ObservableObject {
    @Published private(set) var state = LockState(locked: false, authenticating: false)
    let manager: AppLockManager
    var onChange: ((LockState) -> Void)?
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []

    init() {
        manager = AppLockManager(storage: UserDefaults.standard, prompt: LockController.prompt)
        state = manager.state
        manager.onChange = { [weak self] s in
            self?.state = s
            self?.onChange?(s)
        }
        let workspace = NSWorkspace.shared.notificationCenter
        let distributed = DistributedNotificationCenter.default()
        let on = { [weak self] (nc: NotificationCenter, name: Notification.Name, act: @escaping @MainActor (LockController) -> Void) in
            let token = nc.addObserver(forName: name, object: nil, queue: .main) { _ in
                MainActor.assumeIsolated { if let self { act(self) } }
            }
            self?.observers.append((nc, token))
        }
        on(distributed, Notification.Name("com.apple.screenIsLocked")) { $0.manager.lock(.screenLocked) }
        on(workspace, NSWorkspace.screensDidSleepNotification) { $0.manager.lock(.screenSlept) }
        on(workspace, NSWorkspace.sessionDidResignActiveNotification) { $0.manager.lock(.sessionSwitched) }
    }

    func unlock() {
        Task { await manager.authenticate() }
    }

    func reset() {
        manager.reset()
    }

    /// Touch ID, or the Mac's password where there is no Touch ID or it fails.
    nonisolated static func prompt() async -> (success: Bool, error: String?) {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            return (false, "unavailable_\(error?.code ?? 0)")
        }
        do {
            let ok = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "unlock Secure App")
            return (ok, ok ? nil : "not_authenticated")
        } catch {
            return (false, "la_\((error as NSError).code)")
        }
    }
}
