import XCTest
@testable import SecureAppKit

/// Reads the TypeScript contract from shared/src and fails if a value the Swift side
/// mirrors no longer appears in it, so a change on one side cannot ship alone.
final class ContractDriftTests: XCTestCase {
    private func repoFile(_ relative: String) throws -> String {
        // app/SecureAppKitTests/ContractDriftTests.swift -> repo root
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent(relative), encoding: .utf8)
    }

    private func assertQuoted(_ values: [String], in source: String, file: StaticString = #filePath, line: UInt = #line) {
        for value in values {
            XCTAssertTrue(source.contains("\"\(value)\""), "\(value) is not in the TypeScript contract", file: file, line: line)
        }
    }

    func testRequestContractMatchesRequestTs() throws {
        let ts = try repoFile("shared/src/request.ts")
        assertQuoted([
            AppHeader.app, AppHeader.key, AppHeader.time, AppHeader.nonce, AppHeader.challenge, AppHeader.assertion,
            AppContract.clientDataVersion, AppContract.attestChallengePath, AppContract.attestRegisterPath,
            AppContract.attestSessionPath, AppContract.sessionBootstrap, AppContract.livePath,
            AppPush.tokenPath, AppPush.testPath,
        ], in: ts)
        XCTAssertTrue(ts.contains("REQUEST_MAX_SKEW_MS = 120 * 1000"))
        XCTAssertEqual(AppContract.maxSkewMs, 120 * 1000)
        XCTAssertTrue(ts.contains("DEVICE_LABEL_MAX = \(AppContract.deviceLabelMax)"))
        XCTAssertTrue(ts.contains("/^[A-Za-z0-9_-]{16,64}$/"))
        XCTAssertTrue(ts.contains("/^[A-Za-z0-9_-]{43}$/"))
        // The field order of the signed string.
        let order = ["CLIENT_DATA_VERSION", "p.appId", "p.keyId", "p.method.toUpperCase()", "p.pathAndQuery", "p.bodySha256", "p.tokenSha256", "String(p.time)", "p.nonce", "p.challenge"]
        var cursor = ts.range(of: "export function clientData")!.upperBound
        for field in order {
            let found = try XCTUnwrap(ts.range(of: field, range: cursor..<ts.endIndex), "\(field) out of order")
            cursor = found.upperBound
        }
    }

    func testBridgeContractMatchesBridgeTs() throws {
        let ts = try repoFile("shared/src/bridge.ts")
        assertQuoted([AppBridge.handlerName, AppBridge.receiver, AppBridge.nativeScheme] + AppBridge.requestHeaders + AppBridge.responseHeaders, in: ts)
        XCTAssertTrue(ts.contains("BRIDGE_MAX_BODY_BYTES = 25 * 1024 * 1024"))
        XCTAssertEqual(AppBridge.maxBodyBytes, 25 * 1024 * 1024)
        XCTAssertTrue(ts.contains("PAGE_BADGE_MAX = 100_000"))
        XCTAssertEqual(AppNav.badgeMax, 100_000)
        for kind in ["fetch", "identity", "signOut", "live", "open", "page", "ok", "refused", "liveState", "session"] {
            XCTAssertTrue(ts.contains("\"\(kind)\""), kind)
        }
        for state in ["locked", "unlocked", "signedOut"] {
            XCTAssertTrue(ts.contains("\"\(state)\""), state)
        }
        XCTAssertTrue(ts.contains("keyId: string"), "identity carries keyId")
        XCTAssertTrue(ts.contains("kind: \"page\"; path: string; title: string; badge: number; nav: NavGroup[]"))
        XCTAssertTrue(ts.contains("interface NavGroup {\n  title: string;\n  items: NavItem[];"))
        XCTAssertTrue(ts.contains("interface NavItem {\n  title: string;\n  path: string;"))
        // The two bridged-path rules that name a path.
        XCTAssertTrue(ts.contains("pathname.startsWith(\"/api/\")"))
        XCTAssertTrue(ts.contains("pathname === \"/api/live\""))
        XCTAssertTrue(ts.contains("pathname.startsWith(\"/api/attest/\")"))
    }

    func testTheSharedVectorsAreTheSameContract() throws {
        let vectors = try GoldenVectorTests.loadVectors()
        XCTAssertEqual(vectors.version, AppContract.clientDataVersion)
        for c in vectors.clientData {
            XCTAssertTrue(matches(noncePattern, c.parts.nonce), c.name)
        }
    }

    func testGateRefusalMessageMatchesTheWorker() throws {
        let worker = try repoFile("worker/src/gate.ts")
        XCTAssertTrue(worker.contains("\"\(AppContract.gateRefusalMessage)\""), "the Worker's refusal message changed")
    }
}
