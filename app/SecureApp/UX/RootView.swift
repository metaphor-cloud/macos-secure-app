import SwiftUI
import SecureAppKit
import WebKit

/// One window, which is one tab. Every window shows the app's
/// phase; when ready, it has its own page and the sidebar.
struct RootView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var lock: LockController
    /// What this window was opened for; nil for the first window.
    let request: TabRequest?
    @State private var tab: AppTab?
    /// The page this tab was on, kept with the window so a restored tab reopens it.
    @SceneStorage("secureapp.route") private var savedRoute: String?
    @Environment(\.openWindow) private var openWindow

    /// Which web generation this window's tab belongs to; nil while not ready.
    private var tabKey: Int? { model.phase == .ready ? model.webGeneration : nil }

    var body: some View {
        ZStack {
            content
                // Covered while locked or in the background: nothing readable in a screenshot, Mission Control or over a shoulder.
                .blur(radius: lock.state.locked ? 28 : 0)
                .allowsHitTesting(!lock.state.locked)
                .accessibilityHidden(lock.state.locked)
            if lock.state.locked {
                LockedView(lock: lock)
            }
        }
        .frame(minWidth: 900, minHeight: 600)
        .background(WindowAccessor(model: model, tab: tab))
        .onAppear {
            if model.openWindow == nil {
                let open = openWindow
                model.openWindow = { request in open(id: "main", value: request) }
            }
            model.start()
        }
        .onChange(of: tabKey, initial: true) { _, key in
            let route = tab?.page?.path ?? request?.route ?? savedRoute
            if let old = tab {
                model.closeTab(old)
                tab = nil
            }
            if key != nil { tab = model.makeTab(route: route) }
        }
        .onDisappear {
            if let tab { model.closeTab(tab) }
        }
    }

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .starting:
            ProgressView().controlSize(.large).frame(maxWidth: .infinity, maxHeight: .infinity)
        case .ready:
            if let tab {
                AppWindowContent(model: model, tab: tab, savedRoute: $savedRoute)
            } else {
                ProgressView().controlSize(.large).frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        case .misconfigured:
            MessageView(symbol: "exclamationmark.triangle", title: Copy.Misconfigured.title, message: Copy.Misconfigured.body)
        case .unsupported:
            MessageView(symbol: "lock.slash", title: Copy.Unsupported.title, message: Copy.Unsupported.body)
        case .signedOut(let notice):
            SignInView(notice: notice) { model.signIn() }
        case .signingIn:
            MessageView(symbol: "person.badge.key", title: Copy.SignIn.title, message: Copy.SignIn.waiting, busy: true)
        case .nameThisMac:
            NameThisMacView(model: model)
        case .enrolling(let stage):
            MessageView(symbol: "laptopcomputer", title: Copy.NameThisMac.title, message: Copy.enrolStage(stage), busy: true)
        case .fullSecurityNeeded:
            MessageView(symbol: "lock.shield", title: Copy.FullSecurity.title, message: Copy.FullSecurity.body,
                        actions: [(Copy.FullSecurity.button, model.retry)], secondary: signOutAction)
        case .appleUnavailable:
            MessageView(symbol: "icloud.slash", title: Copy.AppleUnavailable.title, message: Copy.AppleUnavailable.body,
                        actions: [(Copy.AppleUnavailable.button, model.retry)], secondary: signOutAction)
        case .ssoRequired:
            MessageView(symbol: "building.2", title: Copy.Sso.title, message: Copy.Sso.body,
                        actions: [(Copy.Sso.button, model.signInWithSso)], secondary: signOutAction)
        case .rateLimited:
            MessageView(symbol: "hourglass", title: Copy.RateLimited.title, message: Copy.RateLimited.body,
                        actions: [(Copy.RateLimited.button, model.retry)], secondary: signOutAction)
        case .enrolRefused:
            MessageView(symbol: "xmark.shield", title: Copy.Refused.title, message: Copy.Refused.body,
                        actions: [(Copy.Refused.button, model.addAgain)], secondary: signOutAction)
        case .unreachable:
            MessageView(symbol: "wifi.slash", title: Copy.Unreachable.title, message: Copy.Unreachable.body,
                        actions: [(Copy.Unreachable.button, model.retry)], secondary: signOutAction)
        case .failed(let reason):
            MessageView(symbol: "exclamationmark.triangle", title: Copy.Failed.title, message: "\(Copy.Failed.body) \(reason)",
                        actions: [(Copy.Failed.button, model.retry)], secondary: signOutAction)
        case .reenrol:
            MessageView(symbol: "laptopcomputer.trianglebadge.exclamationmark", title: Copy.Reenrol.title, message: Copy.Reenrol.body,
                        actions: [(Copy.Reenrol.button, model.addAgain)], secondary: signOutAction)
        case .clockWrong:
            MessageView(symbol: "clock.badge.exclamationmark", title: Copy.Clock.title, message: Copy.Clock.body,
                        actions: [(Copy.Clock.button, model.retry)], secondary: signOutAction)
        }
    }

    private var signOutAction: (String, () -> Void) {
        (Copy.NameThisMac.signOut, { model.signOut() })
    }
}

struct WebViewHost: NSViewRepresentable {
    let webView: WKWebView

    func makeNSView(context: Context) -> WKWebView { webView }
    func updateNSView(_ view: WKWebView, context: Context) {}
}

struct MessageView: View {
    let symbol: String
    let title: String
    let message: String
    var busy = false
    var actions: [(String, () -> Void)] = []
    var secondary: (String, () -> Void)?

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: symbol)
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(.secondary)
            Text(title).font(.title2).bold().multilineTextAlignment(.center)
            Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 440)
            if busy { ProgressView().padding(.top, 4) }
            HStack(spacing: 12) {
                if let secondary { Button(secondary.0, action: secondary.1) }
                ForEach(actions.indices, id: \.self) { i in
                    Button(actions[i].0, action: actions[i].1).keyboardShortcut(.defaultAction)
                }
            }
            .padding(.top, 8)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct SignInView: View {
    let notice: String?
    let signIn: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 96, height: 96)
            Text(Copy.SignIn.title).font(.largeTitle).bold()
            Text(Copy.SignIn.body).foregroundStyle(.secondary)
            if let notice {
                Text(notice).foregroundStyle(.orange).multilineTextAlignment(.center).frame(maxWidth: 420)
            }
            Button(Copy.SignIn.button, action: signIn).keyboardShortcut(.defaultAction).controlSize(.large)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct NameThisMacView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "laptopcomputer").font(.system(size: 44, weight: .light)).foregroundStyle(.secondary)
            Text(Copy.NameThisMac.title).font(.title2).bold()
            Text(Copy.NameThisMac.body).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 440)
            if let who = model.identity {
                Text(who.email).font(.callout).foregroundStyle(.secondary)
            }
            TextField(Copy.NameThisMac.field, text: $model.proposedLabel)
                .textFieldStyle(.roundedBorder)
                .frame(width: 320)
                .onSubmit { model.enrol() }
            HStack(spacing: 12) {
                Button(Copy.NameThisMac.signOut) { model.signOut() }
                Button(Copy.NameThisMac.button) { model.enrol() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(cleanDeviceLabel(model.proposedLabel) == nil)
            }
            .padding(.top, 8)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct LockedView: View {
    @ObservedObject var lock: LockController

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill").font(.system(size: 40)).foregroundStyle(.secondary)
            Text(Copy.Lock.title).font(.title2).bold()
            Button(Copy.Lock.button) { lock.unlock() }
                .keyboardShortcut(.defaultAction)
                .controlSize(.large)
                .disabled(lock.state.authenticating)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.regularMaterial)
    }
}
