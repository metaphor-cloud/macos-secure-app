import XCTest
@testable import SecureAppKit

/// The parts of Mac push that are not AppKit glue.
final class PushTests: XCTestCase {
    func testTokenIsLowerCaseHexTwoCharactersAByte() {
        XCTAssertEqual(apnsTokenHex(Data([0x00, 0x0f, 0xab, 0xff])), "000fabff")
        XCTAssertEqual(apnsTokenHex(Data(repeating: 0xA1, count: 32)).count, 64)
        XCTAssertEqual(apnsTokenHex(Data()), "")
    }

    func testRegisterRequestCarriesTokenKindAndEnvironment() throws {
        let request = try XCTUnwrap(pushRegisterRequest(token: Data([0xde, 0xad, 0xbe, 0xef]), environment: .development))
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.pathAndQuery, "/api/push/token")
        XCTAssertEqual(request.headers["Content-Type"], "application/json")
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(request.body)) as? [String: String])
        XCTAssertEqual(body, ["token": "deadbeef", "environment": "development"])
        // The key comes from the signature, never the body.
        XCTAssertNil(body["keyId"])
    }

    func testNoRequestForAnEmptyToken() {
        XCTAssertNil(pushRegisterRequest(token: Data(), environment: .production))
    }

    func testUnregisterIsADeleteOfTheSamePath() {
        let request = pushUnregisterRequest()
        XCTAssertEqual(request.method, "DELETE")
        XCTAssertEqual(request.pathAndQuery, AppPush.tokenPath)
        XCTAssertNil(request.body)
    }

    func testPushPathsAreBridgedPaths() {
        XCTAssertTrue(isBridgedPath(AppPush.tokenPath))
        XCTAssertTrue(isBridgedPath(AppPush.testPath))
    }

    func testThePayloadsPathBecomesARoute() {
        XCTAssertEqual(appRoute(forPushPath: "#/notes"), "/notes")
        XCTAssertEqual(appRoute(forPushPath: "/notes/abc"), "/notes/abc")
        XCTAssertEqual(appRoute(fromPushUserInfo: ["aps": ["badge": 2], "path": "#/notes"]), "/notes")
    }

    func testAnythingThatIsNotARouteIsIgnored() {
        for path in ["", "notes", "https://evil.example/notes", "#/notes/../x", "#//x", "/n\u{0}x", "/" + String(repeating: "a", count: 600)] {
            XCTAssertNil(appRoute(forPushPath: path), path)
        }
        XCTAssertNil(appRoute(fromPushUserInfo: ["aps": [:]]))
        XCTAssertNil(appRoute(fromPushUserInfo: ["path": 42]))
        XCTAssertNil(appRoute(fromPushUserInfo: ["path": NSNull()]))
    }
}
