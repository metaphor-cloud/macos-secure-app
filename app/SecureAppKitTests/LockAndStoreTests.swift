import XCTest
@testable import SecureAppKit

/// The screen locking locks the app, and only the prompt unlocks it.
@MainActor
final class AppLockManagerTests: XCTestCase {
    let storage = InMemoryLockStorage()
    var promptResult = true
    var prompts = 0

    func make() -> AppLockManager {
        AppLockManager(storage: storage, prompt: { [unowned self] in
            prompts += 1
            return (promptResult, promptResult ? nil : "user_cancel")
        })
    }

    func testStartsUnlocked() {
        XCTAssertFalse(make().state.locked)
    }

    func testAScreenLockNeedsThePromptToUnlock() async {
        let lock = make()
        lock.lock(.screenLocked)
        XCTAssertTrue(lock.state.locked)
        promptResult = false
        await lock.authenticate()
        XCTAssertTrue(lock.state.locked, "a failed prompt leaves it locked")
        promptResult = true
        await lock.authenticate()
        XCTAssertFalse(lock.state.locked)
        XCTAssertEqual(prompts, 2)
        XCTAssertNil(storage.string(forKey: AppLockManager.lockedKey))
    }

    func testAnUnlockedAppDoesNotPrompt() async {
        let lock = make()
        await lock.authenticate()
        XCTAssertEqual(prompts, 0)
    }

    func testQuittingWhileLockedLaunchesLocked() {
        make().lock(.screenSlept)
        XCTAssertTrue(make().state.locked)
    }

    func testLockNowAndASessionSwitchLockToo() {
        let lock = make()
        lock.lock(.menu)
        XCTAssertTrue(lock.state.locked)
        lock.reset()
        lock.lock(.sessionSwitched)
        XCTAssertTrue(lock.state.locked)
    }

    func testResetForgetsEverything() {
        let lock = make()
        lock.lock(.screenLocked)
        lock.reset()
        XCTAssertFalse(lock.state.locked)
        XCTAssertNil(storage.string(forKey: AppLockManager.lockedKey))
        XCTAssertFalse(make().state.locked)
    }
}

final class SecureStoreTests: XCTestCase {
    func testInMemoryStoreRoundTripsAndRemoves() throws {
        let store = InMemorySecureStore()
        XCTAssertNil(try store.data(for: "a"))
        try store.set(Data("1".utf8), for: "a")
        try store.set(Data("2".utf8), for: "a")
        XCTAssertEqual(try store.data(for: "a"), Data("2".utf8))
        try store.remove("a")
        try store.remove("a")
        XCTAssertNil(try store.data(for: "a"))
    }

    func testKeysArePerSubAndSurviveSignOut() throws {
        let store = InMemorySecureStore()
        let keys = AttestKeyStore(store: store)
        try keys.save(AttestKeyRecord(keyId: "k1", enrolled: true, deviceLabel: "Mac"), for: "sub_a")
        try keys.save(AttestKeyRecord(keyId: "k2", enrolled: false, deviceLabel: "Mac"), for: "sub_b")
        XCTAssertEqual(keys.record(for: "sub_a")?.keyId, "k1")
        XCTAssertEqual(keys.record(for: "sub_b")?.keyId, "k2")
        keys.discard(for: "sub_a")
        XCTAssertNil(keys.record(for: "sub_a"))
        XCTAssertEqual(store.accounts, ["attest-key.sub_b"])
    }

    func testAnUnreadableRecordIsDiscarded() throws {
        let store = InMemorySecureStore()
        try store.set(Data("garbage".utf8), for: "attest-key.sub_a")
        XCTAssertNil(AttestKeyStore(store: store).record(for: "sub_a"))
        XCTAssertEqual(store.accounts, [])
    }

    func testDeviceLabelIsCleanedAndCut() {
        XCTAssertEqual(cleanDeviceLabel("  Ru\u{7}'s Mac \n"), "Ru's Mac")
        XCTAssertNil(cleanDeviceLabel("  \n"))
        XCTAssertEqual(cleanDeviceLabel(String(repeating: "m", count: 100))?.count, 64)
    }
}

final class OIDCTests: XCTestCase {
    func testPKCEChallengeIsS256OfTheVerifier() {
        // Expected value from an independent implementation:
        // printf %s <verifier> | openssl dgst -sha256 -binary | base64, made URL-safe without padding.
        let pkce = PKCE(verifier: "dBjftJeZ4CVP-mJ92K27uhbUJU1p1r_wW1gFWFOEjXk")
        XCTAssertEqual(pkce.challenge, "ngF5GsXcbwljx6u133FFr3Xht9xooA_DuaX_3QwODtc")
    }

    func testIdentityFromTheIdToken() {
        let payload = Data(#"{"sub":"sub_1","email":"sam@example.com","name":"Sam"}"#.utf8).base64URLEncodedString()
        XCTAssertEqual(AppIdentity(idToken: "h.\(payload).s"), AppIdentity(sub: "sub_1", email: "sam@example.com", name: "Sam"))
        XCTAssertNil(AppIdentity(idToken: "nope"))
    }

    func testCallbackChecksStateAndErrors() throws {
        let req = AuthorizationRequest(url: URL(string: "https://id/a")!, state: "s1", nonce: "n", pkce: .make())
        XCTAssertEqual(try OIDCClient.code(from: URL(string: "secureapp-mac://auth?code=abc&state=s1")!, for: req), "abc")
        XCTAssertThrowsError(try OIDCClient.code(from: URL(string: "secureapp-mac://auth?code=abc&state=other")!, for: req))
        XCTAssertThrowsError(try OIDCClient.code(from: URL(string: "secureapp-mac://auth?error=access_denied&state=s1")!, for: req))
    }

    // Nothing steers Metaphor ID to a passkey: enrolment needs the org's SSO.
    func testAuthorizationRequestAsksForNoAcrAndAFreshSignInOnlyWhenForced() async throws {
        let transport = FakeTransport()
        transport.on("/.well-known/openid-configuration", 200, ["issuer": "https://metaphor.id", "authorization_endpoint": "https://metaphor.id/authorize", "token_endpoint": "https://metaphor.id/token"])
        let config = AppConfig(apiBase: URL(string: "https://api.test")!, issuer: URL(string: "https://metaphor.id")!, clientId: "c", redirectURI: URL(string: "secureapp-mac://auth")!, appId: "a")
        let oidc = OIDCClient(config: config, transport: transport)
        func items(_ forceLogin: Bool) async throws -> [String: String] {
            let url = try await oidc.authorizationRequest(forceLogin: forceLogin).url
            let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
            return Dictionary(uniqueKeysWithValues: query.map { ($0.name, $0.value ?? "") })
        }
        let normal = try await items(false)
        XCTAssertNil(normal["acr_values"])
        XCTAssertNil(normal["prompt"])
        let forced = try await items(true)
        XCTAssertNil(forced["acr_values"])
        XCTAssertEqual(forced["prompt"], "login")
    }

    func testTokenRefreshKeepsTheOldRefreshAndIdTokenWhenNotRotated() async throws {
        let transport = FakeTransport()
        transport.on("/.well-known/openid-configuration", 200, ["issuer": "https://metaphor.id", "authorization_endpoint": "https://metaphor.id/authorize", "token_endpoint": "https://metaphor.id/token"])
        transport.on("/token", 200, ["access_token": "new", "expires_in": 3600])
        let config = AppConfig(apiBase: URL(string: "https://api.test")!, issuer: URL(string: "https://metaphor.id")!, clientId: "c", redirectURI: URL(string: "secureapp-mac://auth")!, appId: "a")
        let oidc = OIDCClient(config: config, transport: transport)
        let manager = TokenManager(store: InMemorySecureStore(), oidc: oidc)
        try await manager.adopt(StoredTokens(accessToken: "old", refreshToken: "r", idToken: "id", expiresAt: Date().addingTimeInterval(-10)))
        let token = try await manager.accessToken()
        XCTAssertEqual(token, "new")
        let current = await manager.current
        XCTAssertEqual(current?.refreshToken, "r")
        XCTAssertEqual(current?.idToken, "id")
    }

    func testARefusedRefreshSignsOut() async throws {
        let transport = FakeTransport()
        transport.on("/.well-known/openid-configuration", 200, ["issuer": "https://metaphor.id", "authorization_endpoint": "https://metaphor.id/authorize", "token_endpoint": "https://metaphor.id/token"])
        transport.on("/token", 400, ["error": "invalid_grant"])
        let config = AppConfig(apiBase: URL(string: "https://api.test")!, issuer: URL(string: "https://metaphor.id")!, clientId: "c", redirectURI: URL(string: "secureapp-mac://auth")!, appId: "a")
        let store = InMemorySecureStore()
        let manager = TokenManager(store: store, oidc: OIDCClient(config: config, transport: transport))
        try await manager.adopt(StoredTokens(accessToken: "old", refreshToken: "r", idToken: nil, expiresAt: nil))
        do {
            _ = try await manager.forceRefresh()
            XCTFail("expected signedOut")
        } catch {
            XCTAssertEqual(error as? AuthError, .signedOut)
        }
        XCTAssertEqual(store.accounts, [])
    }
}
