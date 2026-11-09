import Foundation

/// The sidebar's pages, as the SPA reports them with every "page" message
/// (the "page" request in shared/src/bridge.ts). The list is the page's: a new screen needs
/// no change here.
public struct AppNavItem: Equatable, Sendable, Identifiable {
    /// A hash route in the SPA, e.g. "/notes".
    public var path: String
    public var title: String
    public var id: String { path }

    public init(path: String, title: String) {
        self.path = path
        self.title = title
    }
}

public struct AppNavGroup: Equatable, Sendable, Identifiable {
    public var title: String
    public var items: [AppNavItem]
    public var id: String { title }

    public init(title: String, items: [AppNavItem]) {
        self.title = title
        self.items = items
    }
}

/// Where one tab is: its hash route, title, a badge count and the nav list.
public struct AppPageState: Equatable, Sendable {
    public var path: String
    public var title: String
    public var badge: Int
    public var nav: [AppNavGroup]

    public init(path: String, title: String, badge: Int, nav: [AppNavGroup]) {
        self.path = path
        self.title = title
        self.badge = badge
        self.nav = nav
    }
}

public enum AppNav {
    /// PAGE_BADGE_MAX in bridge.ts. The rest are this side's bounds on what a page may report.
    public static let badgeMax = 100_000
    public static let maxGroups = 20
    public static let maxItems = 40
    public static let textMax = 60
    public static let titleMax = 200
    public static let routeMax = 500

    /// Whether a nav item lights up for a hash route: the route's query and trailing slash dropped.
    public static func matches(_ item: AppNavItem, route: String) -> Bool {
        var path = route.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
        while path.count > 1 && path.hasSuffix("/") { path.removeLast() }
        // The root only matches itself, or it would light up for every page.
        if item.path == "/" { return path == "/" }
        return path == item.path || path.hasPrefix(item.path + "/")
    }

    /// The nav item for a route: the longest match.
    public static func item(for route: String, in nav: [AppNavGroup]) -> AppNavItem? {
        var best: AppNavItem?
        for group in nav {
            for item in group.items where matches(item, route: route) {
                if best == nil || item.path.count > best!.path.count { best = item }
            }
        }
        return best
    }

    /// A hash route the shell will load or send a tab to: absolute, short, no control
    /// characters, nothing that climbs out of the page's own routes.
    public static func isRoute(_ route: String) -> Bool {
        guard route.hasPrefix("/"), route.utf8.count <= routeMax,
              !route.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return false }
        let path = route.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
        return !path.contains("..") && !path.contains("//")
    }

    /// A route as the page writes it ("#/notes") or as the shell keeps it ("/notes").
    static func route(from raw: String) -> String {
        raw.hasPrefix("#") ? String(raw.dropFirst()) : raw
    }

    /// What the Dock badge says for a count.
    public static func badgeText(_ count: Int) -> String? {
        guard count > 0 else { return nil }
        return count > 99 ? "99+" : String(count)
    }

    static func cleanText(_ value: Any?, max: Int) -> String? {
        guard let text = value as? String else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= max,
              !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        return trimmed
    }

    /// The "page" message, checked: every field present, in bounds, and every route a route.
    public static func parsePage(_ dict: [String: Any]) -> Result<AppPageState, BridgeRefusal> {
        guard let rawPath = dict["path"] as? String, let rawTitle = dict["title"] as? String, let badge = dict["badge"] as? Int,
              let rawNav = dict["nav"] as? [Any] else { return .failure(.malformed) }
        let path = route(from: rawPath)
        guard isRoute(path) else { return .failure(.pathNotAllowed) }
        guard (0...badgeMax).contains(badge), rawNav.count <= maxGroups, let title = cleanText(rawTitle, max: titleMax) else {
            return .failure(.pageNotAllowed)
        }
        var nav: [AppNavGroup] = []
        var itemCount = 0
        for rawGroup in rawNav {
            guard let group = rawGroup as? [String: Any], group["title"] is String, let rawItems = group["items"] as? [Any] else {
                return .failure(.malformed)
            }
            guard let groupTitle = cleanText(group["title"], max: textMax) else { return .failure(.pageNotAllowed) }
            var items: [AppNavItem] = []
            for rawItem in rawItems {
                guard let item = rawItem as? [String: Any], item["title"] is String, let rawItemPath = item["path"] as? String else {
                    return .failure(.malformed)
                }
                let itemPath = route(from: rawItemPath)
                guard isRoute(itemPath), let itemTitle = cleanText(item["title"], max: textMax) else { return .failure(.pageNotAllowed) }
                items.append(AppNavItem(path: itemPath, title: itemTitle))
            }
            itemCount += items.count
            guard itemCount <= maxItems else { return .failure(.pageNotAllowed) }
            nav.append(AppNavGroup(title: groupTitle, items: items))
        }
        return .success(AppPageState(path: path, title: title, badge: badge, nav: nav))
    }
}

/// What to do with a navigation in a tab's web view: a link into the bundled SPA
/// with the command key or the middle button, or one asking for a new window,
/// opens in a new tab; everything else goes on as before.
public enum AppLinkDisposition: Equatable, Sendable {
    case newTab(route: String)
    case proceed

    /// `url` is the navigation's target; the bundled SPA's links are secureapp://app/index.html#/notes/...
    public static func decide(url: URL, commandKey: Bool, middleButton: Bool, wantsNewWindow: Bool) -> AppLinkDisposition {
        guard commandKey || middleButton || wantsNewWindow else { return .proceed }
        guard let route = appRoute(of: url) else { return .proceed }
        return .newTab(route: route)
    }

    /// The hash route of a link into the bundled SPA, or nil.
    public static func appRoute(of url: URL) -> String? {
        guard url.scheme == AppBridge.appScheme, url.host == AppBridge.appHost, let fragment = url.fragment else { return nil }
        let route = fragment.removingPercentEncoding ?? fragment
        return AppNav.isRoute(route) ? route : nil
    }
}
