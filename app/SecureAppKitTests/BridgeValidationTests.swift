import XCTest
@testable import SecureAppKit

final class BridgeValidationTests: XCTestCase {
    func testOnlyTheBundledPageMayPointAFrameAtASignedLoad() {
        XCTAssertTrue(AppBridge.allowsNativeFrameNavigation(from: URL(string: "secureapp://app/notes")))
        // A preview redirecting itself, or a frame with no known source.
        XCTAssertFalse(AppBridge.allowsNativeFrameNavigation(from: URL(string: "about:srcdoc")))
        XCTAssertFalse(AppBridge.allowsNativeFrameNavigation(from: URL(string: "about:blank")))
        XCTAssertFalse(AppBridge.allowsNativeFrameNavigation(from: URL(string: "secureapp-native:///api/x")))
        XCTAssertFalse(AppBridge.allowsNativeFrameNavigation(from: URL(string: "secureapp://evil/x")))
        XCTAssertFalse(AppBridge.allowsNativeFrameNavigation(from: nil))
    }

    // The rules of isBridgedApiPath in shared/src/bridge.ts, one for one.
    func testCarriesApiPathsWithQueries() {
        XCTAssertTrue(isBridgedPath("/api/notes?limit=10"))
        XCTAssertTrue(isBridgedPath("/api/notes/abc/export"))
        XCTAssertTrue(isBridgedPath("/api/me"))
        XCTAssertTrue(isBridgedPath("/api/livestock"), "only /api/live itself is native-only")
        XCTAssertTrue(isBridgedPath(AppPush.tokenPath))
    }

    func testRefusesEverythingElseIncludingNativeOnlyPaths() {
        for path in ["/api/attest", "/api/attest/register", "/api/attest/session", "/api/attest/challenge", "/api/live", "/api", "/account", "https://evil.example/api/x", "api/x", ""] {
            XCTAssertFalse(isBridgedPath(path), path)
        }
        XCTAssertFalse(isBridgedPath(AppContract.livePath))
        XCTAssertFalse(isBridgedPath(AppContract.attestRegisterPath))
    }

    func testRefusesPathsThatClimbOutOfThePrefix() {
        XCTAssertFalse(isBridgedPath("/api/../account"))
        XCTAssertFalse(isBridgedPath("/api/%2e%2e/account"))
        XCTAssertFalse(isBridgedPath("/api//x"))
        XCTAssertFalse(isBridgedPath("/api/%2E%2E/account"))
        XCTAssertFalse(isBridgedPath("/api/a%2Fb"))
    }

    // Targets the Worker's URL parser would rewrite, so the signature would fail.
    func testRefusesNonCanonicalTargets() {
        for path in ["/api/x?", "/api/./x", "/api/a/../x", "/api/x#frag", "/api/x y", "/api/x?q='a'", "/api\\x", "/api/caf\u{e9}", "/api/%zz"] {
            XCTAssertFalse(isCanonicalRequestTarget(path), path)
        }
        for path in ["/api/notes?q=a%20b&limit=10", "/api/x/y-z_1.json", "/api/notes/abc/export"] {
            XCTAssertTrue(isCanonicalRequestTarget(path), path)
        }
    }

    func testParsesAFetchAndKeepsOnlyAllowListedHeaders() throws {
        let result = BridgeValidator.parse([
            "kind": "fetch", "method": "post", "path": "/api/notes",
            "headers": ["content-type": "application/json", "Authorization": "Bearer stolen", "X-App-Key": "x", "Accept": "application/json", "Cookie": "a=b"],
            "body": ["encoding": "text", "data": #"{"title":"hi"}"#],
        ] as [String: Any])
        guard case .success(.fetch(let request)) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.headers, ["Content-Type": "application/json", "Accept": "application/json"])
        XCTAssertEqual(request.body, Data(#"{"title":"hi"}"#.utf8))
    }

    func testRefusesWithReasonCodes() {
        func reason(_ body: Any) -> String? {
            if case .failure(let r) = BridgeValidator.parse(body) { return r.rawValue }
            return nil
        }
        XCTAssertEqual(reason("nope"), "malformed")
        XCTAssertEqual(reason(["kind": "eval"]), "unknown_kind")
        XCTAssertEqual(reason(["kind": "fetch", "method": "GET", "path": "/api/attest/session"]), "path_not_allowed")
        XCTAssertEqual(reason(["kind": "fetch", "method": "GET", "path": "/api/live"]), "path_not_allowed")
        XCTAssertEqual(reason(["kind": "fetch", "method": "GET", "path": "/api/x?"]), "path_not_canonical")
        XCTAssertEqual(reason(["kind": "fetch", "method": "TRACE", "path": "/api/x"]), "method_not_allowed")
        XCTAssertEqual(reason(["kind": "fetch", "method": "GET", "path": "/api/x", "body": ["encoding": "text", "data": "x"]] as [String: Any]), "body_not_allowed")
        XCTAssertEqual(reason(["kind": "fetch", "method": "POST", "path": "/api/x", "body": ["encoding": "base64", "data": "***"]] as [String: Any]), "body_malformed")
        XCTAssertEqual(reason(["kind": "fetch", "method": "POST", "path": "/api/x", "body": ["encoding": "hex", "data": "00"]] as [String: Any]), "body_malformed")
        XCTAssertEqual(reason(["kind": "open", "path": "/account"]), "path_not_allowed")
        XCTAssertEqual(reason(["kind": "live"]), "malformed")
    }

    func testBodySizeCapAtTwentyFiveMegabytes() {
        let max = AppBridge.maxBodyBytes
        let atCap = BridgeValidator.decodeBody(["encoding": "base64", "data": Data(count: max).base64EncodedString()])
        XCTAssertEqual(try? atCap.get().count, max)
        let over = BridgeValidator.decodeBody(["encoding": "base64", "data": Data(count: max + 1).base64EncodedString()])
        XCTAssertEqual(over, .failure(.bodyTooLarge))
        let overText = BridgeValidator.decodeBody(["encoding": "text", "data": String(repeating: "a", count: max + 1)])
        XCTAssertEqual(overText, .failure(.bodyTooLarge))
    }

    func testOtherKinds() {
        XCTAssertEqual(try? BridgeValidator.parse(["kind": "identity"]).get(), .identity)
        XCTAssertEqual(try? BridgeValidator.parse(["kind": "signOut"]).get(), .signOut)
        XCTAssertEqual(try? BridgeValidator.parse(["kind": "live", "on": true] as [String: Any]).get(), .live(on: true))
        XCTAssertEqual(
            try? BridgeValidator.parse(["kind": "open", "path": "/api/notes/abc/export", "suggestedName": "../../etc/passwd"]).get(),
            .open(path: "/api/notes/abc/export", suggestedName: "etcpasswd")
        )
    }

    func testResponseHeadersAreFiltered() {
        let out = BridgeValidator.filterResponseHeaders(["content-type": "text/csv", "Set-Cookie": "a=b", "Content-Disposition": "attachment", "retry-after": "5", "X-Other": "1"])
        XCTAssertEqual(out, ["Content-Type": "text/csv", "Content-Disposition": "attachment", "Retry-After": "5"])
    }

    func testFileNamesAreCleaned() {
        XCTAssertEqual(BridgeValidator.sanitiseFileName("note-1.md"), "note-1.md")
        XCTAssertEqual(BridgeValidator.sanitiseFileName("a/b:c\\d"), "abcd")
        XCTAssertEqual(BridgeValidator.sanitiseFileName("..hidden"), "hidden")
        XCTAssertNil(BridgeValidator.sanitiseFileName("  / "))
        XCTAssertEqual(BridgeValidator.sanitiseFileName(String(repeating: "a", count: 300))?.count, 200)
    }
}
