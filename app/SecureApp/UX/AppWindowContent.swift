import AppKit
import SwiftUI
import SecureAppKit

/// A ready window: the native sidebar beside this tab's page.
struct AppWindowContent: View {
    @ObservedObject var model: AppModel
    @ObservedObject var tab: AppTab
    @Binding var savedRoute: String?

    var body: some View {
        NavigationSplitView {
            AppSidebar(model: model, tab: tab)
                .navigationSplitViewColumnWidth(min: 190, ideal: 220, max: 300)
        } detail: {
            WebViewHost(webView: tab.web.webView)
        }
        .navigationTitle(tab.title)
        .onChange(of: tab.page?.path) { _, path in
            if let path { savedRoute = path }
        }
    }
}

/// The pages, from the list the page sends with every "page" message.
/// A click moves this tab; ⌘-click or Open in New Tab opens the page in a new tab.
struct AppSidebar: View {
    @ObservedObject var model: AppModel
    @ObservedObject var tab: AppTab

    /// The row for this tab's page, as NavLink matched it.
    private var current: String? {
        guard let path = tab.page?.path else { return nil }
        return AppNav.item(for: path, in: model.nav)?.path
    }

    private var selection: Binding<String?> {
        Binding(
            get: { current },
            set: { picked in
                guard let picked, picked != current else { return }
                if NSEvent.modifierFlags.contains(.command) {
                    model.openTab(route: picked)
                } else {
                    tab.navigate(route: picked)
                }
            }
        )
    }

    var body: some View {
        List(selection: selection) {
            ForEach(model.nav) { group in
                Section(group.title) {
                    ForEach(group.items) { item in
                        Text(item.title)
                            .tag(item.path)
                            .contextMenu {
                                Button(Copy.Menu.openInNewTab) { model.openTab(route: item.path) }
                            }
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            if let who = model.identity {
                VStack(alignment: .leading, spacing: 2) {
                    Text(Copy.Sidebar.signedInAs).font(.caption2).foregroundStyle(.secondary)
                    Text(who.email).font(.caption).lineLimit(1).truncationMode(.middle)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                // Opaque, so the list scrolling under it doesn't show through the text.
                .background(.bar)
                .overlay(alignment: .top) { Divider() }
            }
        }
    }
}

/// The window behind a RootView: tabs join the window they were opened from,
/// and the key window's tab is the one the menus act on.
struct WindowAccessor: NSViewRepresentable {
    let model: AppModel
    let tab: AppTab?

    func makeNSView(context: Context) -> WindowWatcher {
        WindowWatcher(model: model)
    }

    func updateNSView(_ view: WindowWatcher, context: Context) {
        view.tab = tab
        if let tab, view.window?.isKeyWindow == true { model.tabBecameActive(tab) }
    }
}

@MainActor
final class WindowWatcher: NSView {
    private let model: AppModel
    weak var tab: AppTab?
    private var observer: NSObjectProtocol?

    init(model: AppModel) {
        self.model = model
        super.init(frame: .zero)
    }

    required init?(coder: NSCoder) { nil }

    static let tabbingIdentifier = "com.example.secureapp.window"

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let observer { NotificationCenter.default.removeObserver(observer) }
        observer = nil
        guard let window else { return }
        window.tabbingIdentifier = Self.tabbingIdentifier
        window.tabbingMode = .preferred
        // A tab asked for from another window (⌘T, ⌘-click): it joins that window's tabs.
        if let parent = model.pendingTabParent, parent !== window, parent.isVisible {
            model.pendingTabParent = nil
            parent.addTabbedWindow(window, ordered: .above)
            window.makeKeyAndOrderFront(nil)
        }
        observer = NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: window, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let tab = self.tab else { return }
                self.model.tabBecameActive(tab)
            }
        }
    }

    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }
}
