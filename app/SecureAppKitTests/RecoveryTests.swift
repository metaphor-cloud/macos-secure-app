import XCTest
@testable import SecureAppKit

/// The uniform 403 recovery (runbook "For app developers" step 7).
final class ForbiddenRecoveryTests: XCTestCase {
    let refusal = try! JSONSerialization.data(withJSONObject: gateRefusal)
    let handler403 = try! JSONSerialization.data(withJSONObject: ["error": "Not allowed"])
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func testSessionThenTokenThenReenrol() {
        var r = ForbiddenRecovery()
        XCTAssertEqual(r.next(status: 403, body: refusal, serverDate: nil, now: now), .refreshSessionAndRetry)
        XCTAssertEqual(r.next(status: 403, body: refusal, serverDate: nil, now: now), .refreshTokenAndRetry)
        XCTAssertEqual(r.next(status: 403, body: refusal, serverDate: nil, now: now), .reenrol)
    }

    func testAHandlersOwn403GoesToThePage() {
        var r = ForbiddenRecovery()
        XCTAssertEqual(r.next(status: 403, body: handler403, serverDate: nil, now: now), .deliver)
        XCTAssertEqual(r.next(status: 403, body: Data("not json".utf8), serverDate: nil, now: now), .deliver)
        XCTAssertEqual(r.next(status: 200, body: Data(), serverDate: nil, now: now), .deliver)
        XCTAssertEqual(r.next(status: 500, body: refusal, serverDate: nil, now: now), .deliver)
    }

    func testA401RefreshesTheTokenOnceThenSignsIn() {
        var r = ForbiddenRecovery()
        XCTAssertEqual(r.next(status: 401, body: Data(), serverDate: nil, now: now), .refreshTokenAndRetry)
        XCTAssertEqual(r.next(status: 401, body: Data(), serverDate: nil, now: now), .signIn)
    }

    func testAClockOutOfSkewIsTheClockNotTheKey() {
        var r = ForbiddenRecovery()
        let server = httpDateFormatter.string(from: now.addingTimeInterval(-600))
        XCTAssertEqual(r.next(status: 403, body: refusal, serverDate: server, now: now), .clockWrong)
        let close = httpDateFormatter.string(from: now.addingTimeInterval(-30))
        XCTAssertEqual(r.next(status: 403, body: refusal, serverDate: close, now: now), .refreshSessionAndRetry)
    }

    func testARefusedSessionRequestGoesToTheTokenThenReenrol() {
        var r = ForbiddenRecovery()
        XCTAssertEqual(r.sessionRefused(serverDate: nil, now: now), .refreshTokenAndRetry)
        XCTAssertEqual(r.sessionRefused(serverDate: nil, now: now), .reenrol)
    }
}

/// The client end to end against a fake Worker: signing order, session bootstrap, recovery, enrolment.
final class AppClientTests: XCTestCase {
    var transport: FakeTransport!
    var attester: FakeAttester!
    var tokens: FakeTokens!
    var store: InMemorySecureStore!
    var keys: AttestKeyStore!
    var events: [AppClientEvent] = []
    let eventsLock = NSLock()

    func makeClient(retry: AttestRetryPolicy = AttestRetryPolicy(), sleeps: SleepLog = SleepLog()) -> AppClient {
        transport = FakeTransport()
        attester = FakeAttester()
        tokens = FakeTokens(access: "access-1")
        store = InMemorySecureStore()
        keys = AttestKeyStore(store: store)
        let config = AppConfig(apiBase: URL(string: "https://api.test")!, issuer: URL(string: "https://metaphor.id")!, clientId: "c", redirectURI: URL(string: "secureapp-mac://auth")!, appId: "TEAMID1234.com.example.secureapp")
        let client = AppClient(config: config, transport: transport, attester: attester, tokens: tokens, keys: keys, retryPolicy: retry, sleep: { await sleeps.add($0) })
        client.onEvent { [weak self] e in self?.eventsLock.withLock { self?.events.append(e) } }
        return client
    }

    func challengeHeaders() -> [String] {
        transport.seen.map { $0.value(forHTTPHeaderField: AppHeader.challenge) ?? "" }
    }

    func testBootstrapsTheSessionThenSignsOverIt() async {
        let client = makeClient()
        await client.use(sub: "sub_1", keyId: "key-1")
        transport.on(AppContract.attestSessionPath, 200, ["challenge": testChallenge, "expiresAt": 1e15])
        transport.on("/api/notes", 200, ["notes": []])
        let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/notes"))
        guard case .response(200, _, _) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(transport.paths(), [AppContract.attestSessionPath, "/api/notes"])
        XCTAssertEqual(challengeHeaders(), [AppContract.sessionBootstrap, testChallenge])
        // The second request reuses the session.
        _ = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/notes"))
        XCTAssertEqual(transport.paths().count, 3)
    }

    func testGateRefusalRefreshesSessionThenTokenThenAsksToReenrol() async {
        let client = makeClient()
        await client.use(sub: "sub_1", keyId: "key-1")
        transport.on(AppContract.attestSessionPath, 200, ["challenge": testChallenge])
        transport.on(AppContract.attestSessionPath, 200, ["challenge": testChallenge2])
        transport.on("/api/x", 403, gateRefusal)
        let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/x"))
        guard case .response(403, _, _) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(transport.paths(), [AppContract.attestSessionPath, "/api/x", AppContract.attestSessionPath, "/api/x", "/api/x"])
        let refreshes = await tokens.refreshes
        XCTAssertEqual(refreshes, 1)
        XCTAssertEqual(events, [.needsReenrol])
        // The retry after the token refresh carried the new token.
        XCTAssertEqual(transport.seen.last?.value(forHTTPHeaderField: "Authorization"), "Bearer refreshed-1")
    }

    func testRecoveryStopsAsSoonAsARetryPasses() async {
        let client = makeClient()
        await client.use(sub: "sub_1", keyId: "key-1")
        transport.on(AppContract.attestSessionPath, 200, ["challenge": testChallenge])
        transport.on("/api/x", 403, gateRefusal)
        transport.on("/api/x", 200, ["ok": true])
        let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/x"))
        guard case .response(200, _, _) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(events, [])
        let refreshes = await tokens.refreshes
        XCTAssertEqual(refreshes, 0)
    }

    func testAHandlers403IsNotRecovered() async {
        let client = makeClient()
        await client.use(sub: "sub_1", keyId: "key-1")
        transport.on(AppContract.attestSessionPath, 200, ["challenge": testChallenge])
        transport.on("/api/forbidden", 403, ["error": "Not allowed"])
        _ = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/forbidden"))
        XCTAssertEqual(transport.paths(), [AppContract.attestSessionPath, "/api/forbidden"])
        XCTAssertEqual(events, [])
    }

    func testRefusedSessionGoesToTokenThenReenrol() async {
        let client = makeClient()
        await client.use(sub: "sub_1", keyId: "key-1")
        transport.on(AppContract.attestSessionPath, 403, gateRefusal)
        let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/x"))
        guard case .failed("reenrol") = result else { return XCTFail("\(result)") }
        XCTAssertEqual(transport.paths(), [AppContract.attestSessionPath, AppContract.attestSessionPath])
        XCTAssertEqual(events, [.needsReenrol])
    }

    func testAnEndedSessionAsksForSignIn() async {
        let client = makeClient()
        await client.use(sub: "sub_1", keyId: "key-1")
        await tokens.setRefreshFails(true)
        transport.on(AppContract.attestSessionPath, 200, ["challenge": testChallenge])
        transport.on("/api/x", 401, ["error": "Not authenticated"])
        let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/x"))
        guard case .failed("signed_out") = result else { return XCTFail("\(result)") }
        XCTAssertEqual(events, [.needsSignIn])
    }

    func testAWrongClockIsReportedNotReenrolled() async {
        let client = makeClient()
        await client.use(sub: "sub_1", keyId: "key-1")
        let farOff = httpDateFormatter.string(from: Date().addingTimeInterval(3600))
        transport.on(AppContract.attestSessionPath, 403, gateRefusal, headers: ["Date": farOff])
        _ = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/x"))
        XCTAssertEqual(events, [.clockWrong])
    }

    func testRequestsAreSignedOneAtATimeInOrder() async {
        let client = makeClient()
        await client.use(sub: "sub_1", keyId: "key-1")
        transport.on(AppContract.attestSessionPath, 200, ["challenge": testChallenge])
        transport.on("/api/a", 200, [:] as [String: Any])
        let inFlight = InFlight()
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<8 {
                group.addTask {
                    _ = await client.performSigned(AppHTTPRequest(method: "GET", pathAndQuery: "/api/a?i=\(i)")) { req in
                        await inFlight.enter()
                        try? await Task.sleep(nanoseconds: 2_000_000)
                        await inFlight.leave()
                        return (Data("{}".utf8), HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!)
                    }
                }
            }
        }
        let max = await inFlight.max
        XCTAssertEqual(max, 1, "never more than one signed request in flight")
        XCTAssertEqual(attester.assertedHashes.count, 9) // the session bootstrap plus eight
    }

    func testAnInvalidKeyIsDiscardedAndReenrolAsked() async throws {
        let client = makeClient()
        try keys.save(AttestKeyRecord(keyId: "key-1", enrolled: true, deviceLabel: "Mac"), for: "sub_1")
        await client.use(sub: "sub_1", keyId: "key-1")
        attester.assertionError = .invalidKey
        let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/x"))
        guard case .failed("reenrol") = result else { return XCTFail("\(result)") }
        XCTAssertNil(keys.record(for: "sub_1"))
        XCTAssertEqual(events, [.needsReenrol])
    }

    func testAKeyTheSecureEnclaveWillNotSignWithIsDiscardedAndReenrolAsked() async throws {
        let client = makeClient()
        try keys.save(AttestKeyRecord(keyId: "key-1", enrolled: true, deviceLabel: "Mac"), for: "sub_1")
        await client.use(sub: "sub_1", keyId: "key-1")
        attester.assertionError = .unknown(code: 0)
        let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/x"))
        guard case .failed("reenrol") = result else { return XCTFail("\(result)") }
        XCTAssertNil(keys.record(for: "sub_1"))
        XCTAssertEqual(events, [.needsReenrol])
    }

    func testAnInvalidInputAssertionKeepsTheKey() async throws {
        let client = makeClient()
        try keys.save(AttestKeyRecord(keyId: "key-1", enrolled: true, deviceLabel: "Mac"), for: "sub_1")
        await client.use(sub: "sub_1", keyId: "key-1")
        attester.assertionError = .invalidInput
        let result = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/x"))
        guard case .failed("assertion_invalid_input") = result else { return XCTFail("\(result)") }
        XCTAssertNotNil(keys.record(for: "sub_1"))
        XCTAssertEqual(events, [])
    }

    // MARK: Enrolment

    func testEnrolsWithTheChallengeHashTheLabelAndTheIdToken() async throws {
        let client = makeClient()
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "enrol-challenge"])
        transport.on(AppContract.attestRegisterPath, 201, ["ok": true, "platform": "macos", "environment": "development", "sessionChallenge": testChallenge, "sessionChallengeExpiresAt": Date().timeIntervalSince1970 * 1000 + 600_000])
        transport.on("/api/x", 200, [:] as [String: Any])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "  Ru's MacBook\n", progress: { _ in })
        XCTAssertEqual(outcome, .enrolled(AttestKeyRecord(keyId: attester.nextKeyId, enrolled: true, deviceLabel: "Ru's MacBook")))
        XCTAssertEqual(attester.attestedHashes.first?.1, sha256(Data("enrol-challenge".utf8)))
        let register = try XCTUnwrap(transport.seen.first { $0.url?.path == AppContract.attestRegisterPath })
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: register.httpBody!) as? [String: Any])
        XCTAssertEqual(body["challenge"] as? String, "enrol-challenge")
        XCTAssertEqual(body["keyId"] as? String, attester.nextKeyId)
        XCTAssertEqual(body["appId"] as? String, "TEAMID1234.com.example.secureapp")
        XCTAssertEqual(body["deviceLabel"] as? String, "Ru's MacBook")
        XCTAssertEqual(body["idToken"] as? String, "id.token.here")
        XCTAssertEqual(body["attestation"] as? String, Data("attestation".utf8).base64EncodedString())
        XCTAssertNil(register.value(forHTTPHeaderField: AppHeader.assertion), "enrolment is bearer only")
        XCTAssertEqual(keys.record(for: "sub_1")?.enrolled, true)
        // The session challenge from /register is used straight away, no bootstrap.
        _ = await client.perform(AppHTTPRequest(method: "GET", pathAndQuery: "/api/x"))
        XCTAssertEqual(transport.seen.last?.value(forHTTPHeaderField: AppHeader.challenge), testChallenge)
    }

    func testUnsupportedIsAHardStop() async {
        let client = makeClient()
        attester.isSupported = false
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .unsupported)
        XCTAssertTrue(transport.seen.isEmpty)
    }

    func testAppleUnavailableRetriesWithTheSameKeyAndHashWithBackoff() async {
        let sleeps = SleepLog()
        let client = makeClient(retry: AttestRetryPolicy(initialDelay: 2, maxDelay: 60, budget: 1000), sleeps: sleeps)
        attester.attestErrors = [.serverUnavailable, .serverUnavailable, .serverUnavailable]
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        transport.on(AppContract.attestRegisterPath, 201, ["sessionChallenge": testChallenge])
        let stages = StageLog()
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { s in Task { await stages.add(s) } })
        guard case .enrolled = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(attester.attestedHashes.count, 4)
        XCTAssertEqual(Set(attester.attestedHashes.map(\.0)).count, 1, "same key")
        XCTAssertEqual(Set(attester.attestedHashes.map(\.1)).count, 1, "same clientDataHash")
        XCTAssertEqual(attester.generated, 1)
        let delays = await sleeps.delays
        XCTAssertEqual(delays, [2, 4, 8])
    }

    func testAppleUnavailablePastTheBudgetKeepsTheKeyForNextTime() async {
        let client = makeClient(retry: AttestRetryPolicy(initialDelay: 2, maxDelay: 60, budget: 0))
        attester.attestErrors = [.serverUnavailable]
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .appleUnavailable)
        XCTAssertEqual(keys.record(for: "sub_1")?.enrolled, false)
        XCTAssertEqual(keys.record(for: "sub_1")?.keyId, attester.nextKeyId)
    }

    func testAnyOtherAttestErrorDiscardsTheKey() async {
        let client = makeClient()
        attester.attestErrors = [.invalidInput]
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .failed(reason: "attest_invalid_input"))
        XCTAssertNil(keys.record(for: "sub_1"))
    }

    func testInvalidKeyAtAttestationAsksForFullSecurity() async {
        let client = makeClient()
        attester.attestErrors = [.invalidKey]
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .fullSecurityNeeded)
        XCTAssertNil(keys.record(for: "sub_1"))
    }

    func testInvalidKeyOnAKeptKeyStartsAgainWithAFreshKeyOnce() async throws {
        let client = makeClient()
        // An earlier try attested this key but /register never answered, so it was kept.
        try keys.save(AttestKeyRecord(keyId: "kept-key", enrolled: false, deviceLabel: "Mac"), for: "sub_1")
        attester.attestErrors = [.invalidKey]
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        transport.on(AppContract.attestRegisterPath, 201, ["sessionChallenge": testChallenge])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .enrolled(AttestKeyRecord(keyId: attester.nextKeyId, enrolled: true, deviceLabel: "Mac")), "not Full Security advice")
        XCTAssertEqual(attester.generated, 1)
        XCTAssertEqual(attester.attestedHashes.map(\.0), ["kept-key", attester.nextKeyId])
        XCTAssertEqual(Set(attester.attestedHashes.map(\.1)), [sha256(Data("c1".utf8))], "same challenge for both keys")
        let register = try XCTUnwrap(transport.seen.first { $0.url?.path == AppContract.attestRegisterPath })
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: register.httpBody!) as? [String: Any])
        XCTAssertEqual(body["keyId"] as? String, attester.nextKeyId)
        XCTAssertEqual(keys.record(for: "sub_1")?.keyId, attester.nextKeyId)
    }

    func testInvalidKeyOnTheFreshKeyAfterAKeptOneAsksForFullSecurityWithoutLooping() async throws {
        let client = makeClient()
        try keys.save(AttestKeyRecord(keyId: "kept-key", enrolled: false, deviceLabel: "Mac"), for: "sub_1")
        attester.attestErrors = [.invalidKey, .invalidKey, .invalidKey]
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .fullSecurityNeeded)
        XCTAssertEqual(attester.generated, 1)
        XCTAssertEqual(attester.attestedHashes.map(\.0), ["kept-key", attester.nextKeyId])
        XCTAssertNil(keys.record(for: "sub_1"))
        XCTAssertFalse(transport.seen.contains { $0.url?.path == AppContract.attestRegisterPath })
    }

    func testOtherAttestErrorsOnAKeptKeyDoNotStartAgain() async throws {
        let client = makeClient()
        try keys.save(AttestKeyRecord(keyId: "kept-key", enrolled: false, deviceLabel: "Mac"), for: "sub_1")
        attester.attestErrors = [.invalidInput]
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .failed(reason: "attest_invalid_input"))
        XCTAssertEqual(attester.generated, 0)
        XCTAssertNil(keys.record(for: "sub_1"))
    }

    func testSsoRequiredDiscardsTheSpentKey() async {
        let client = makeClient()
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        transport.on(AppContract.attestRegisterPath, 403, ["error": "This device could not be added.", "sso": "required"])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .ssoRequired)
        XCTAssertNil(keys.record(for: "sub_1"))
    }

    func testWorkerRefusingTheKeyPolicyAsksForFullSecurity() async {
        let client = makeClient()
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        transport.on(AppContract.attestRegisterPath, 403, ["error": "This device could not be added.", "device": "full_security"])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .fullSecurityNeeded)
        XCTAssertNil(keys.record(for: "sub_1"))
    }

    func testOtherRegisterAnswers() async {
        for (status, expected) in [(401, EnrolOutcome.signIn), (429, .rateLimited), (403, .refused)] {
            let client = makeClient()
            transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
            transport.on(AppContract.attestRegisterPath, status, ["error": "x"])
            let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
            XCTAssertEqual(outcome, expected, "\(status)")
        }
        let client = makeClient()
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        transport.on(AppContract.attestRegisterPath, 409, ["error": "x"])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        guard case .enrolled = outcome else { return XCTFail("409 is already enrolled") }
    }

    func testTheWorkerFailingIsUnreachableAndKeepsTheKey() async {
        let client = makeClient()
        transport.on(AppContract.attestChallengePath, 200, ["challenge": "c1"])
        transport.on(AppContract.attestRegisterPath, 503, ["error": "x"])
        let outcome = await client.enrol(sub: "sub_1", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(outcome, .unreachable)
        XCTAssertNotNil(keys.record(for: "sub_1"), "the attested key is tried again, not thrown away")

        let early = makeClient()
        transport.on(AppContract.attestChallengePath, 500, ["error": "x"])
        let failed = await early.enrol(sub: "sub_2", deviceLabel: "Mac", progress: { _ in })
        XCTAssertEqual(failed, .unreachable)
    }

    func testRetryPolicyBacksOffAndStopsAtTheBudget() {
        let p = AttestRetryPolicy(initialDelay: 2, maxDelay: 60, budget: 240)
        XCTAssertEqual(p.delay(attempt: 0, elapsed: 0), 2)
        XCTAssertEqual(p.delay(attempt: 3, elapsed: 0), 16)
        XCTAssertEqual(p.delay(attempt: 10, elapsed: 0), 60)
        XCTAssertNil(p.delay(attempt: 5, elapsed: 200))
    }
}

actor SleepLog {
    var delays: [TimeInterval] = []
    func add(_ d: TimeInterval) { delays.append(d) }
}

actor StageLog {
    var stages: [EnrolStage] = []
    func add(_ s: EnrolStage) { stages.append(s) }
}

actor InFlight {
    var now = 0
    var max = 0
    func enter() {
        now += 1
        max = Swift.max(max, now)
    }

    func leave() { now -= 1 }
}
