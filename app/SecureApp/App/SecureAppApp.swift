import SwiftUI
import SecureAppKit

@main
struct SecureAppApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    @AppStorage(Appearance.key) private var appearance = Appearance.system.rawValue

    var body: some Scene {
        // A window is a tab, each with its own web view. They share one signer, one
        // live socket and one lock through AppModel. Frames, tabs and each tab's page are restored
        // by the system; a first launch opens the last page.
        WindowGroup(id: "main", for: TabRequest.self) { $request in
            RootView(model: model, lock: model.lock, request: request)
        }
        .defaultSize(width: 1280, height: 820)
        .commands {
            CommandGroup(after: .toolbar) {
                Button(Copy.Menu.reload) { model.reload() }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(model.phase != .ready)
                Picker(Copy.Menu.appearance, selection: $appearance) {
                    ForEach(Appearance.allCases) { Text($0.label).tag($0.rawValue) }
                }
                .onChange(of: appearance) { _, raw in Appearance.apply(raw) }
            }
            CommandGroup(replacing: .newItem) {
                Button(Copy.Menu.newTab) { model.openTab(route: nil) }
                    .keyboardShortcut("t", modifiers: .command)
                    .disabled(model.phase != .ready)
            }
            CommandGroup(after: .appSettings) {
                Button(Copy.Menu.lock) { model.lock.manager.lock(.menu) }
                    .keyboardShortcut("l", modifiers: [.command, .control])
                    .disabled(model.phase != .ready)
                Button(Copy.Menu.signOut) { model.signOut() }
                    .disabled(model.identity == nil)
            }
        }

        Settings {
            SettingsView(model: model, mcp: model.mcp)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        PushNotifications.shared.install()
        Appearance.apply(UserDefaults.standard.string(forKey: Appearance.key))
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Log.app.info("launched")
    }

    func application(_ application: NSApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        PushNotifications.shared.didRegister(token: deviceToken)
    }

    func application(_ application: NSApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        PushNotifications.shared.didFailToRegister(error)
    }
}

/// System, Light or Dark for every window. The pages follow the
/// window's appearance, so this is the theme control the web sidebar used to have.
enum Appearance: String, CaseIterable, Identifiable {
    case system, light, dark

    static let key = "secureapp.appearance"
    var id: String { rawValue }

    var label: String {
        switch self {
        case .system: Copy.Menu.appearanceSystem
        case .light: Copy.Menu.appearanceLight
        case .dark: Copy.Menu.appearanceDark
        }
    }

    @MainActor static func apply(_ raw: String?) {
        switch Appearance(rawValue: raw ?? "") ?? .system {
        case .system: NSApp.appearance = nil
        case .light: NSApp.appearance = NSAppearance(named: .aqua)
        case .dark: NSApp.appearance = NSAppearance(named: .darkAqua)
        }
    }
}
