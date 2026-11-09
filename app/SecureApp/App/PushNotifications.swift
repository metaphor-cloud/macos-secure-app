import AppKit
import SecureAppKit
import UserNotifications

/// Push notifications on the Mac: permission, the APNs token, taps
/// and the Dock badge the payload sets. The rules are in SecureAppKit/Contract/AppPush.swift;
/// this is the AppKit and UserNotifications glue around them.
///
/// Permission is asked once the Mac is signed in and enrolled, never at
/// launch. The token goes to the Worker through the signed client,
/// never the web view, and again whenever macOS hands over a token, which
/// covers a token that changed. Sign-out deletes it.
@MainActor
final class PushNotifications: NSObject, UNUserNotificationCenterDelegate {
    static let shared = PushNotifications()

    private var client: AppClient?
    /// Opens a route in the web view. Set while the page is up.
    var openRoute: ((String) -> Void)?
    /// A tap that arrived before the page was up: the launch tap.
    private var pendingRoute: String?

    /// From applicationWillFinishLaunching, so a tap that launches the app is delivered.
    func install() {
        UNUserNotificationCenter.current().delegate = self
    }

    /// Signed in on an enrolled Mac: ask for permission if not yet asked, then register with APNs.
    func enable(client: AppClient) {
        self.client = client
        Task {
            let center = UNUserNotificationCenter.current()
            let granted: Bool
            do {
                granted = try await center.requestAuthorization(options: [.alert, .badge, .sound])
            } catch {
                Log.app.notice("push not registered, reason: permission_error")
                return
            }
            guard granted else {
                Log.app.info("push not registered, reason: permission_denied")
                return
            }
            NSApplication.shared.registerForRemoteNotifications()
        }
    }

    /// On sign-out, while the session is still there: the Worker forgets this Mac's token and the badge clears.
    func signOut() async {
        setBadge(0)
        guard let client else { return }
        self.client = nil
        let result = await client.perform(pushUnregisterRequest())
        if case .response(let status, _, _) = result, (200..<300).contains(status) {
            Log.app.info("push token removed")
        } else {
            Log.app.notice("push token not removed")
        }
    }

    // MARK: Token

    func didRegister(token: Data) {
        guard let client, let request = pushRegisterRequest(token: token, environment: .current) else {
            Log.app.notice("push token not sent, reason: not_signed_in")
            return
        }
        Task {
            let result = await client.perform(request)
            switch result {
            case .response(let status, _, _) where (200..<300).contains(status):
                Log.app.info("push token registered, environment: \(APNsEnvironment.current.rawValue, privacy: .public)")
            case .response(let status, _, _):
                Log.app.notice("push token not registered, reason: server_refused, status: \(status, privacy: .public)")
            case .failed(let reason):
                Log.app.notice("push token not registered, reason: \(reason, privacy: .public)")
            }
        }
    }

    func didFailToRegister(_ error: Error) {
        // A build without the aps-environment entitlement lands here.
        Log.app.error("push registration failed, code: \((error as NSError).code, privacy: .public)")
    }

    // MARK: Taps

    /// The route a launch tap asked for, once.
    func takePendingRoute() -> String? {
        defer { pendingRoute = nil }
        return pendingRoute
    }

    private func open(_ route: String) {
        NSApplication.shared.activate()
        NSApplication.shared.windows.first { $0.canBecomeMain }?.makeKeyAndOrderFront(nil)
        if let openRoute {
            openRoute(route)
        } else {
            pendingRoute = route
        }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        let route = response.actionIdentifier == UNNotificationDefaultActionIdentifier
            ? appRoute(fromPushUserInfo: response.notification.request.content.userInfo)
            : nil
        Task { @MainActor in
            if let route {
                Log.app.info("notification opened")
                self.open(route)
            }
            completionHandler()
        }
    }

    /// Banners while the app is open too, and the payload's badge.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound, .badge])
    }

    // MARK: Badge

    /// Clears the Dock badge, on sign-out.
    func setBadge(_ count: Int) {
        UNUserNotificationCenter.current().setBadgeCount(count) { error in
            if error != nil { Log.app.debug("badge not set") }
        }
    }
}
