import XCTest
@testable import SecureAppKit

/// The MCP: protocol shapes, argument validation, the person's confirmation, and the HTTP guard.
final class AppMCPTests: XCTestCase {
    final class Recorder: @unchecked Sendable {
        var sent: [AppHTTPRequest] = []
        var prompts: [MCPConfirmation] = []
        var approve = true
        var ready = true
        var replies: [String: (Int, Any)] = [:]
        private let lock = NSLock()

        func perform(_ request: AppHTTPRequest) -> AppResult {
            lock.withLock { sent.append(request) }
            let key = request.method + " " + request.pathAndQuery
            let (status, json) = replies[key] ?? (200, ["ok": true])
            return .response(status: status, headers: [:], body: try! JSONSerialization.data(withJSONObject: json))
        }
    }

    let rec = Recorder()

    func makeHandler() -> AppMCPHandler {
        AppMCPHandler(
            perform: { [rec] in rec.perform($0) },
            confirm: { [rec] c in rec.prompts.append(c); return rec.approve },
            isReady: { [rec] in rec.ready },
            makeReference: { "ref-1" }
        )
    }

    func rpc(_ method: String, _ params: [String: Any] = [:], id: Any? = 1) async -> [String: Any] {
        var message: [String: Any] = ["jsonrpc": "2.0", "method": method, "params": params]
        if let id { message["id"] = id }
        let reply = await makeHandler().handle(try! JSONSerialization.data(withJSONObject: message))
        guard let body = reply.body else { return ["status": reply.status] }
        return try! JSONSerialization.jsonObject(with: body) as! [String: Any]
    }

    func call(_ name: String, _ args: [String: Any]) async -> [String: Any] {
        let reply = await rpc("tools/call", ["name": name, "arguments": args])
        return reply["result"] as! [String: Any]
    }

    func text(_ result: [String: Any]) -> String {
        ((result["content"] as! [[String: Any]])[0])["text"] as! String
    }

    // MARK: Protocol

    func testInitializeEchoesASupportedVersionElseTheFirst() async {
        for v in AppMCPHandler.supportedProtocolVersions {
            let r = (await rpc("initialize", ["protocolVersion": v]))["result"] as! [String: Any]
            XCTAssertEqual(r["protocolVersion"] as? String, v)
        }
        let r = (await rpc("initialize", ["protocolVersion": "1999-01-01"]))["result"] as! [String: Any]
        XCTAssertEqual(r["protocolVersion"] as? String, "2026-07-28")
        XCTAssertEqual((r["serverInfo"] as! [String: Any])["name"] as? String, "secure-app")
    }

    func testNotificationsGetNoBody() async {
        let reply = await makeHandler().handle(Data(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.utf8))
        XCTAssertEqual(reply.status, 202)
        XCTAssertNil(reply.body)
    }

    func testPingAndUnknownMethodAndBadInput() async {
        let pong = await rpc("ping")
        XCTAssertNotNil(pong["result"])
        let unknown = (await rpc("resources/list"))["error"] as! [String: Any]
        XCTAssertEqual(unknown["code"] as? Int, -32601)
        let bad = await makeHandler().handle(Data("not json".utf8))
        XCTAssertEqual(bad.status, 400)
        let batch = await makeHandler().handle(Data("[]".utf8))
        XCTAssertEqual(batch.status, 400)
    }

    func testToolsListShape() async {
        let tools = ((await rpc("tools/list"))["result"] as! [String: Any])["tools"] as! [[String: Any]]
        XCTAssertEqual(tools.map { $0["name"] as! String }, ["get_me", "list_notes", "create_note"])
        for tool in tools {
            XCTAssertNotNil(tool["title"])
            XCTAssertEqual((tool["inputSchema"] as! [String: Any])["type"] as? String, "object")
            let a = tool["annotations"] as! [String: Any]
            XCTAssertNotNil(a["readOnlyHint"])
            XCTAssertNotNil(a["destructiveHint"])
        }
        let create = tools.first { $0["name"] as? String == "create_note" }!
        XCTAssertEqual((create["annotations"] as! [String: Any])["readOnlyHint"] as? Bool, false)
        let list = tools.first { $0["name"] as? String == "list_notes" }!
        XCTAssertEqual((list["annotations"] as! [String: Any])["readOnlyHint"] as? Bool, true)
    }

    // MARK: Reads

    func testGetMeReturnsStructuredContent() async {
        rec.replies["GET /api/me"] = (200, ["email": "sam@example.com", "name": "Sam"])
        let result = await call("get_me", [:])
        XCTAssertEqual(rec.sent.map(\.pathAndQuery), ["/api/me"])
        XCTAssertNil(result["isError"])
        XCTAssertEqual((result["structuredContent"] as! [String: Any])["email"] as? String, "sam@example.com")
        XCTAssertTrue(rec.prompts.isEmpty, "reads are not confirmed")
    }

    func testListNotesCountsThem() async {
        rec.replies["GET /api/notes"] = (200, ["notes": [["id": "n1"], ["id": "n2"]]])
        let result = await call("list_notes", [:])
        XCTAssertEqual(rec.sent.map(\.pathAndQuery), ["/api/notes"])
        XCTAssertTrue(text(result).hasPrefix("2 notes."))
        XCTAssertTrue(rec.prompts.isEmpty)
        rec.replies["GET /api/notes"] = (200, ["notes": []])
        let empty = await call("list_notes", [:])
        XCTAssertTrue(text(empty).hasPrefix("No notes."))
    }

    func testAnArrayBodyIsWrapped() async {
        rec.replies["GET /api/notes"] = (200, [1, 2, 3])
        let result = await call("list_notes", [:])
        XCTAssertEqual((result["structuredContent"] as! [String: Any])["items"] as? [Int], [1, 2, 3])
    }

    func testServerRefusalBecomesAToolError() async {
        rec.replies["GET /api/notes"] = (503, ["error": "Try later"])
        let result = await call("list_notes", [:])
        XCTAssertEqual(result["isError"] as? Bool, true)
        XCTAssertEqual(text(result), "Try later")
        XCTAssertEqual((result["structuredContent"] as! [String: Any])["reason"] as? String, "http_503")
    }

    func testAFailedRequestIsAToolErrorWithItsReason() async {
        let handler = AppMCPHandler(perform: { _ in .failed(reason: "signed_out") }, confirm: { _ in true }, isReady: { true })
        let body = #"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_me","arguments":{}}}"#
        let reply = await handler.handle(Data(body.utf8))
        let result = (try! JSONSerialization.jsonObject(with: reply.body!) as! [String: Any])["result"] as! [String: Any]
        XCTAssertEqual(result["isError"] as? Bool, true)
        XCTAssertEqual((result["structuredContent"] as! [String: Any])["reason"] as? String, "request_failed")
        XCTAssertTrue(text(result).contains("signed_out"))
    }

    func testUnknownToolIsAToolError() async {
        let r = await call("drop_database", [:])
        XCTAssertEqual(r["isError"] as? Bool, true)
        XCTAssertEqual((r["structuredContent"] as! [String: Any])["reason"] as? String, "unknown_tool")
    }

    // MARK: Validation

    func testNoteArgumentsAreBounded() async {
        let bad: [[String: Any]] = [
            [:],
            ["title": ""],
            ["title": "   "],
            ["title": 5],
            ["title": String(repeating: "a", count: 121)],
            ["title": "ok", "body": String(repeating: "a", count: 10_001)],
            ["title": "ok", "body": 5],
        ]
        for args in bad {
            let r = await call("create_note", args)
            XCTAssertEqual(r["isError"] as? Bool, true, "\(args)")
        }
        XCTAssertTrue(rec.sent.isEmpty, "nothing reached the API")
        XCTAssertTrue(rec.prompts.isEmpty, "nothing was asked")
    }

    func testArgValidatorsRefuseInjection() throws {
        for id in ["../../devices", "abc/export", "abc?x=1", "abc#", "a b", "", String(repeating: "a", count: 65), "abc%2F..", "a\nb", ".."] {
            XCTAssertThrowsError(try MCPArgs.id(["id": id], "id"), id)
        }
        XCTAssertEqual(try MCPArgs.id(["id": "a-b_C1"], "id"), "a-b_C1")
        XCTAssertEqual(MCPArgs.queryValue("a&b=c d/é"), "a%26b%3Dc%20d%2F%C3%A9")
        XCTAssertThrowsError(try MCPArgs.oneOf(["s": "x&y"], "s", ["a", "b"], default: "a"))
        XCTAssertEqual(try MCPArgs.oneOf([:], "s", ["a", "b"], default: "a"), "a")
    }

    // MARK: Writes

    func testADeclinedWriteSendsNothing() async {
        rec.approve = false
        let result = await call("create_note", ["title": "Plan", "body": "Do it"])
        XCTAssertEqual(result["isError"] as? Bool, true)
        XCTAssertEqual(text(result), AppMCPHandler.declined)
        XCTAssertEqual(rec.prompts.count, 1)
        XCTAssertTrue(rec.sent.isEmpty, "no write left the app")
    }

    func testAnAcceptedNoteSendsExactlyTheExpectedRequest() async throws {
        rec.replies["POST /api/notes"] = (201, ["note": ["id": "n1", "title": "Plan"]])
        let result = await call("create_note", ["title": "  Plan  ", "body": "Do it"])
        XCTAssertNil(result["isError"])
        XCTAssertEqual(rec.sent.count, 1)
        let expectedBody = try JSONSerialization.data(withJSONObject: ["title": "Plan", "body": "Do it"], options: [.sortedKeys])
        XCTAssertEqual(rec.sent[0], AppHTTPRequest(method: "POST", pathAndQuery: "/api/notes", headers: ["Content-Type": "application/json", "Accept": "application/json"], body: expectedBody))
        // The person saw the exact text first.
        XCTAssertEqual(rec.prompts.count, 1)
        XCTAssertFalse(rec.prompts[0].destructive)
        XCTAssertTrue(rec.prompts[0].detail.contains("Plan"))
        XCTAssertTrue(rec.prompts[0].detail.contains("Do it"))
        XCTAssertEqual((result["structuredContent"] as! [String: Any])["note"] as? [String: String], ["id": "n1", "title": "Plan"])
    }

    func testLockingWhileTheQuestionIsOpenSendsNothing() async {
        let handler = AppMCPHandler(
            perform: { [rec] in rec.perform($0) },
            confirm: { [rec] _ in rec.ready = false; return true },
            isReady: { [rec] in rec.ready }
        )
        let body = #"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_note","arguments":{"title":"x"}}}"#
        let reply = await handler.handle(Data(body.utf8))
        let result = (try! JSONSerialization.jsonObject(with: reply.body!) as! [String: Any])["result"] as! [String: Any]
        XCTAssertEqual(result["isError"] as? Bool, true)
        XCTAssertTrue(rec.sent.isEmpty)
    }

    func testNothingRunsWhileTheAppIsNotReady() async {
        rec.ready = false
        let result = await call("list_notes", [:])
        XCTAssertEqual(result["isError"] as? Bool, true)
        XCTAssertEqual(text(result), AppMCPHandler.notReady)
        XCTAssertTrue(rec.sent.isEmpty)
        // Protocol housekeeping still answers.
        let listed = await rpc("tools/list")
        XCTAssertNotNil(listed["result"])
    }
}

/// The HTTP guard and the secret.
final class MCPHTTPTests: XCTestCase {
    let port: UInt16 = 47821
    let secret = "secureapp_secret"

    func head(_ lines: [String], method: String = "POST", target: String = "/mcp") -> MCPHTTPHead {
        let raw = "\(method) \(target) HTTP/1.1\r\n" + lines.joined(separator: "\r\n") + "\r\n\r\n"
        return MCPHTTPHead.parse(Data(raw.utf8))!.head
    }

    var good: [String] { ["Host: 127.0.0.1:47821", "Authorization: Bearer secureapp_secret", "Content-Length: 10"] }

    func testAGoodRequestPasses() {
        XCTAssertNil(MCPHTTPGuard.check(head(good), port: port, secret: secret))
        XCTAssertNil(MCPHTTPGuard.check(head(["Host: localhost:47821"] + good.dropFirst()), port: port, secret: secret))
        XCTAssertNil(MCPHTTPGuard.check(head(["host: LocalHost:47821", "authorization: bearer secureapp_secret", "content-length: 0"]), port: port, secret: secret))
    }

    func testOnlyPostToMcp() {
        for method in ["GET", "OPTIONS", "PUT", "DELETE"] {
            XCTAssertEqual(MCPHTTPGuard.check(head(good, method: method), port: port, secret: secret), .methodNotAllowed)
        }
        XCTAssertEqual(MCPHTTPGuard.check(head(good, target: "/other"), port: port, secret: secret), .notFound)
        XCTAssertEqual(MCPHTTPGuard.check(head(good, target: "/mcp?x=1"), port: port, secret: secret), .notFound)
    }

    func testAnOriginHeaderIsRefused() {
        XCTAssertEqual(MCPHTTPGuard.check(head(good + ["Origin: https://evil.example"]), port: port, secret: secret), .originPresent)
        XCTAssertEqual(MCPHTTPGuard.check(head(good + ["Origin: null"]), port: port, secret: secret), .originPresent)
    }

    func testOtherHostsAreRefused() {
        let rest = Array(good.dropFirst())
        for host in ["evil.example:47821", "127.0.0.1", "127.0.0.1:1234", "localhost", "127.0.0.1:47821.evil.example", "0.0.0.0:47821"] {
            XCTAssertEqual(MCPHTTPGuard.check(head(["Host: \(host)"] + rest), port: port, secret: secret), .hostNotAllowed, host)
        }
        XCTAssertEqual(MCPHTTPGuard.check(head(rest), port: port, secret: secret), .hostNotAllowed)
    }

    func testTheSecretIsRequired() {
        let host = "Host: 127.0.0.1:47821"
        XCTAssertEqual(MCPHTTPGuard.check(head([host, "Content-Length: 1"]), port: port, secret: secret), .unauthorised)
        XCTAssertEqual(MCPHTTPGuard.check(head([host, "Authorization: Bearer nope", "Content-Length: 1"]), port: port, secret: secret), .unauthorised)
        XCTAssertEqual(MCPHTTPGuard.check(head([host, "Authorization: Basic secureapp_secret", "Content-Length: 1"]), port: port, secret: secret), .unauthorised)
        XCTAssertEqual(MCPHTTPGuard.check(head([host, "Authorization: Bearer ", "Content-Length: 1"]), port: port, secret: secret), .unauthorised)
        XCTAssertEqual(MCPHTTPGuard.check(head([host, "Authorization: Bearer secureapp_secret", "Authorization: Bearer secureapp_secret", "Content-Length: 1"]), port: port, secret: secret), .unauthorised, "a repeated header is refused")
        XCTAssertTrue(MCPHTTPGuard.constantTimeEqual("a", "a"))
        XCTAssertFalse(MCPHTTPGuard.constantTimeEqual("a", "ab"))
    }

    func testBodyRules() {
        let base = ["Host: 127.0.0.1:47821", "Authorization: Bearer secureapp_secret"]
        XCTAssertEqual(MCPHTTPGuard.check(head(base), port: port, secret: secret), .lengthRequired)
        XCTAssertEqual(MCPHTTPGuard.check(head(base + ["Transfer-Encoding: chunked"]), port: port, secret: secret), .lengthRequired)
        XCTAssertEqual(MCPHTTPGuard.check(head(base + ["Content-Length: 262145"]), port: port, secret: secret), .bodyTooLarge)
        XCTAssertEqual(MCPHTTPGuard.check(head(base + ["Content-Length: 1", "Content-Length: 2"]), port: port, secret: secret), .badRequest)
    }

    func testParsingWaitsForTheWholeHeadAndFindsTheBody() {
        XCTAssertNil(MCPHTTPHead.parse(Data("POST /mcp HTTP/1.1\r\nHost: x".utf8)))
        XCTAssertNil(MCPHTTPHead.parse(Data("garbage\r\n\r\n".utf8)))
        let data = Data("POST /mcp HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}".utf8)
        let parsed = MCPHTTPHead.parse(data)!
        XCTAssertEqual(data.dropFirst(parsed.consumed), Data("{}".utf8))
        XCTAssertEqual(parsed.head.contentLength, 2)
    }

    func testTheSecretIsRandomStoredAndRegenerable() {
        let store = InMemorySecureStore()
        let secrets = MCPSecretStore(store: store)
        let first = secrets.current()!
        XCTAssertTrue(first.hasPrefix("secureapp_"))
        XCTAssertGreaterThanOrEqual(first.count, 40)
        XCTAssertEqual(secrets.current(), first, "stable until regenerated")
        XCTAssertEqual(MCPSecretStore(store: store).current(), first, "survives a restart")
        let second = secrets.regenerate()!
        XCTAssertNotEqual(first, second)
        XCTAssertEqual(secrets.current(), second)
        XCTAssertFalse(MCPHTTPGuard.constantTimeEqual(first, second))
    }
}
