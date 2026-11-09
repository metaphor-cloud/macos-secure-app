import XCTest
@testable import SecureAppKit

/// The shared golden vectors (shared/vectors/request.json, made by
/// `npm run generate:vectors` from shared/src/request.ts). The Worker and this
/// app check the same strings and hashes, so neither can drift. The file is
/// read from ../shared relative to app/, found through #filePath.
final class GoldenVectorTests: XCTestCase {
    struct Vectors: Decodable {
        struct Sha256Case: Decodable { var name: String; var input: String; var sha256: String }
        struct Parts: Decodable {
            var appId: String
            var keyId: String
            var method: String
            var pathAndQuery: String
            var bodySha256: String
            var tokenSha256: String
            var time: Int64
            var nonce: String
            var challenge: String
        }
        struct ClientDataCase: Decodable { var name: String; var parts: Parts; var clientData: String; var clientDataSha256: String }
        struct CanonicalCase: Decodable { var name: String; var input: String; var expected: String }
        var version: String
        var sha256: [Sha256Case]
        var clientData: [ClientDataCase]
        var canonicalRequestTarget: [CanonicalCase]
    }

    static func loadVectors() throws -> Vectors {
        // app/SecureAppKitTests/GoldenVectorTests.swift -> app -> repo root
        let app = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let file = app.deletingLastPathComponent().appendingPathComponent("shared/vectors/request.json")
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: file))
    }

    func testTheVersionIsTheContractsVersion() throws {
        XCTAssertEqual(try Self.loadVectors().version, AppContract.clientDataVersion)
    }

    func testHashesEveryInputAsTheVectorsSay() throws {
        let vectors = try Self.loadVectors()
        XCTAssertFalse(vectors.sha256.isEmpty)
        for c in vectors.sha256 {
            XCTAssertEqual(sha256Hex(c.input), c.sha256, c.name)
        }
    }

    func testBuildsExactlyTheSignedStringByteForByte() throws {
        let vectors = try Self.loadVectors()
        XCTAssertFalse(vectors.clientData.isEmpty)
        for c in vectors.clientData {
            let built = appClientData(Self.requestParts(c.parts))
            XCTAssertEqual(Array(built.utf8), Array(c.clientData.utf8), c.name)
            XCTAssertEqual(sha256Hex(built), c.clientDataSha256, c.name)
        }
    }

    func testNoRewrittenTargetIsEverSent() throws {
        // The Worker hashes what its URL parser makes of a target. A target the parser would change
        // is refused by the bridge, so the one that is signed is the one the Worker sees.
        let vectors = try Self.loadVectors()
        XCTAssertFalse(vectors.canonicalRequestTarget.isEmpty)
        for c in vectors.canonicalRequestTarget {
            XCTAssertEqual(isCanonicalRequestTarget(c.input), c.input == c.expected, "\(c.name): \(c.input)")
        }
    }

    func testSignerSignsEachVectorRequest() async throws {
        // The signer, given the vector's inputs, hands App Attest exactly the vector's hash.
        for c in try Self.loadVectors().clientData {
            let attester = FakeAttester()
            let config = AppConfig(apiBase: URL(string: "https://api.test")!, issuer: URL(string: "https://metaphor.id")!, clientId: "c", redirectURI: URL(string: "secureapp-mac://auth")!, appId: c.parts.appId)
            let now = Date(timeIntervalSince1970: Double(c.parts.time) / 1000)
            let client = AppClient(config: config, transport: FakeTransport(), attester: attester, tokens: FakeTokens(access: "eyJ.test.token"), keys: AttestKeyStore(store: InMemorySecureStore()), now: { now })
            // The vector's body is not kept, only its hash, so a request with the hash's own body is not rebuilt here:
            // the empty-body vectors are signed end to end, the others are covered by the string check above.
            guard c.parts.bodySha256 == sha256Hex(Data()) else { continue }
            let request = AppHTTPRequest(method: c.parts.method, pathAndQuery: c.parts.pathAndQuery)
            let signed = try await client.sign(request, keyId: c.parts.keyId, token: "eyJ.test.token", challenge: c.parts.challenge)

            let nonce = try XCTUnwrap(signed.value(forHTTPHeaderField: AppHeader.nonce))
            XCTAssertTrue(matches(noncePattern, nonce))
            var expected = Self.requestParts(c.parts)
            expected.nonce = nonce
            XCTAssertEqual(attester.assertedHashes.last, sha256(Data(appClientData(expected).utf8)), c.name)
            XCTAssertEqual(signed.url?.absoluteString, "https://api.test" + c.parts.pathAndQuery)
            XCTAssertEqual(signed.httpMethod, c.parts.method.uppercased())
            XCTAssertEqual(signed.value(forHTTPHeaderField: "Authorization"), "Bearer eyJ.test.token")
            XCTAssertEqual(signed.value(forHTTPHeaderField: AppHeader.app), c.parts.appId)
            XCTAssertEqual(signed.value(forHTTPHeaderField: AppHeader.key), c.parts.keyId)
            XCTAssertEqual(signed.value(forHTTPHeaderField: AppHeader.time), String(c.parts.time))
            XCTAssertEqual(signed.value(forHTTPHeaderField: AppHeader.challenge), c.parts.challenge)
            XCTAssertNotNil(signed.value(forHTTPHeaderField: AppHeader.assertion))
            XCTAssertNil(signed.httpBody)
        }
    }

    func testSignerHashesABodyIntoTheRequest() async throws {
        let attester = FakeAttester()
        let config = AppConfig(apiBase: URL(string: "https://api.test")!, issuer: URL(string: "https://metaphor.id")!, clientId: "c", redirectURI: URL(string: "secureapp-mac://auth")!, appId: "TEAMID1234.com.example.secureapp")
        let client = AppClient(config: config, transport: FakeTransport(), attester: attester, tokens: FakeTokens(access: "t"), keys: AttestKeyStore(store: InMemorySecureStore()), now: { Date(timeIntervalSince1970: 1_792_800_000) })
        let body = Data(#"{"title":"Hello","body":"First note"}"#.utf8)
        let request = AppHTTPRequest(method: "post", pathAndQuery: "/api/notes?dry=1", headers: ["Content-Type": "application/json"], body: body)
        let signed = try await client.sign(request, keyId: "k", token: "t", challenge: "c")
        XCTAssertEqual(signed.httpBody, body)
        let nonce = try XCTUnwrap(signed.value(forHTTPHeaderField: AppHeader.nonce))
        let parts = AppRequestParts(appId: config.appId, keyId: "k", method: "POST", pathAndQuery: "/api/notes?dry=1", bodySha256: sha256Hex(body), tokenSha256: sha256Hex("t"), time: 1_792_800_000_000, nonce: nonce, challenge: "c")
        XCTAssertEqual(attester.assertedHashes.last, sha256(Data(appClientData(parts).utf8)))
        XCTAssertEqual(signed.value(forHTTPHeaderField: "Content-Type"), "application/json")
    }

    func testNoncesFitTheContract() {
        for _ in 0..<50 { XCTAssertTrue(matches(noncePattern, makeNonce())) }
    }

    static func requestParts(_ p: Vectors.Parts) -> AppRequestParts {
        AppRequestParts(appId: p.appId, keyId: p.keyId, method: p.method, pathAndQuery: p.pathAndQuery, bodySha256: p.bodySha256, tokenSha256: p.tokenSha256, time: p.time, nonce: p.nonce, challenge: p.challenge)
    }
}
