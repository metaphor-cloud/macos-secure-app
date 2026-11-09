import XCTest
@testable import SecureAppKit

/// The sidebar's nav list from the page, and which links open a new tab.
final class AppNavTests: XCTestCase {
    private func page(nav: Any = [["title": "Notes", "items": [["title": "All notes", "path": "#/notes"]]]],
                      path: Any = "#/notes/abc?tab=1", title: Any = "A note", badge: Any = 3) -> [String: Any] {
        ["kind": "page", "path": path, "title": title, "badge": badge, "nav": nav]
    }

    func testParsesAPageMessageAndKeepsRoutesWithoutTheHash() throws {
        let nav: [Any] = [
            ["title": "Notes", "items": [["title": "Home", "path": "#/"], ["title": "All notes", "path": "/notes"]]],
            ["title": "Account", "items": [["title": "Devices", "path": "#/devices"]]],
        ]
        guard case .success(.page(let state)) = BridgeValidator.parse(page(nav: nav)) else { return XCTFail("not parsed") }
        XCTAssertEqual(state.path, "/notes/abc?tab=1")
        XCTAssertEqual(state.title, "A note")
        XCTAssertEqual(state.badge, 3)
        XCTAssertEqual(state.nav, [
            AppNavGroup(title: "Notes", items: [AppNavItem(path: "/", title: "Home"), AppNavItem(path: "/notes", title: "All notes")]),
            AppNavGroup(title: "Account", items: [AppNavItem(path: "/devices", title: "Devices")]),
        ])
    }

    func testRefusesAPageThatIsNotARoute() {
        for path in ["https://evil.example/x", "/notes/../x", "/notes//x", "notes", "", "#notes"] {
            XCTAssertEqual(refusal(BridgeValidator.parse(page(path: path))), .pathNotAllowed, path)
        }
    }

    func testRefusesANavItemThatIsNotARoute() {
        let nav: [Any] = [["title": "Evil", "items": [["title": "Evil", "path": "https://evil.example"]]]]
        XCTAssertEqual(refusal(BridgeValidator.parse(page(nav: nav))), .pageNotAllowed)
    }

    func testRefusesOutOfBoundsTitlesCountsAndLists() {
        XCTAssertEqual(refusal(BridgeValidator.parse(page(title: String(repeating: "x", count: 201)))), .pageNotAllowed)
        XCTAssertEqual(refusal(BridgeValidator.parse(page(title: "   "))), .pageNotAllowed)
        XCTAssertEqual(refusal(BridgeValidator.parse(page(title: "a\u{0}b"))), .pageNotAllowed)
        XCTAssertEqual(refusal(BridgeValidator.parse(page(badge: -1))), .pageNotAllowed)
        XCTAssertEqual(refusal(BridgeValidator.parse(page(badge: 100_001))), .pageNotAllowed)
        XCTAssertNil(refusal(BridgeValidator.parse(page(badge: 100_000))))
        let tooMany: [Any] = [["title": "G", "items": (0..<41).map { ["title": "P\($0)", "path": "/p\($0)"] }]]
        XCTAssertEqual(refusal(BridgeValidator.parse(page(nav: tooMany))), .pageNotAllowed)
        let groups: [Any] = (0..<21).map { ["title": "G\($0)", "items": []] as [String: Any] }
        XCTAssertEqual(refusal(BridgeValidator.parse(page(nav: groups))), .pageNotAllowed)
        let longTitle: [Any] = [["title": String(repeating: "g", count: 61), "items": []]]
        XCTAssertEqual(refusal(BridgeValidator.parse(page(nav: longTitle))), .pageNotAllowed)
    }

    func testRefusesMalformedPages() {
        XCTAssertEqual(refusal(BridgeValidator.parse(page(badge: "3"))), .malformed)
        XCTAssertEqual(refusal(BridgeValidator.parse(page(nav: "nav"))), .malformed)
        let noTitle: [Any] = [["items": []]]
        XCTAssertEqual(refusal(BridgeValidator.parse(page(nav: noTitle))), .malformed)
        let badItem: [Any] = [["title": "G", "items": [["path": "/x"]]]]
        XCTAssertEqual(refusal(BridgeValidator.parse(page(nav: badItem))), .malformed)
    }

    func testMatchesTheLongestRouteAndTheRootOnlyItself() {
        let home = AppNavItem(path: "/", title: "Home")
        let notes = AppNavItem(path: "/notes", title: "Notes")
        let archive = AppNavItem(path: "/notes/archive", title: "Archive")
        XCTAssertTrue(AppNav.matches(home, route: "/"))
        XCTAssertFalse(AppNav.matches(home, route: "/notes"))
        XCTAssertTrue(AppNav.matches(notes, route: "/notes/"))
        XCTAssertTrue(AppNav.matches(notes, route: "/notes/abc?x=1"))
        XCTAssertFalse(AppNav.matches(notes, route: "/notes-old"))
        let nav = [AppNavGroup(title: "G", items: [home, notes, archive])]
        XCTAssertEqual(AppNav.item(for: "/notes/archive/2", in: nav), archive)
        XCTAssertEqual(AppNav.item(for: "/notes/abc", in: nav), notes)
        XCTAssertEqual(AppNav.item(for: "/", in: nav), home)
        XCTAssertNil(AppNav.item(for: "/other", in: nav))
    }

    func testBadgeText() {
        XCTAssertNil(AppNav.badgeText(0))
        XCTAssertEqual(AppNav.badgeText(7), "7")
        XCTAssertEqual(AppNav.badgeText(99), "99")
        XCTAssertEqual(AppNav.badgeText(100), "99+")
    }

    // MARK: Links

    private let note = URL(string: "secureapp://app/index.html#/notes/abc")!

    func testCommandOrMiddleClickOnALinkInTheAppOpensANewTab() {
        XCTAssertEqual(AppLinkDisposition.decide(url: note, commandKey: true, middleButton: false, wantsNewWindow: false), .newTab(route: "/notes/abc"))
        XCTAssertEqual(AppLinkDisposition.decide(url: note, commandKey: false, middleButton: true, wantsNewWindow: false), .newTab(route: "/notes/abc"))
        XCTAssertEqual(AppLinkDisposition.decide(url: note, commandKey: false, middleButton: false, wantsNewWindow: true), .newTab(route: "/notes/abc"))
    }

    func testAPlainClickStaysInTheTab() {
        XCTAssertEqual(AppLinkDisposition.decide(url: note, commandKey: false, middleButton: false, wantsNewWindow: false), .proceed)
    }

    func testOnlyRoutesInTheBundleOpenAsTabs() {
        for url in ["https://example.com/#/notes", "secureapp://evil/index.html#/notes", "secureapp://app/index.html", "secureapp://app/index.html#notes", "secureapp-native:///api/x"] {
            XCTAssertEqual(AppLinkDisposition.decide(url: URL(string: url)!, commandKey: true, middleButton: false, wantsNewWindow: true), .proceed, url)
        }
    }

    private func refusal(_ result: Result<BridgeRequest, BridgeRefusal>) -> BridgeRefusal? {
        if case .failure(let r) = result { return r }
        return nil
    }
}
