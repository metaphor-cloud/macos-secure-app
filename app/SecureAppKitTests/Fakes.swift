import Foundation
@testable import SecureAppKit

final class FakeAttester: Attester, @unchecked Sendable {
    var isSupported = true
    var nextKeyId = "a2V5LWlkLWZvci10ZXN0cw=="
    var generated = 0
    var attestErrors: [AttestError] = []
    var attestedHashes: [(String, Data)] = []
    var assertedHashes: [Data] = []
    var assertionError: AttestError?
    private let lock = NSLock()

    func generateKey() async throws -> String {
        lock.withLock { generated += 1 }
        return nextKeyId
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        let error: AttestError? = lock.withLock {
            attestedHashes.append((keyId, clientDataHash))
            return attestErrors.isEmpty ? nil : attestErrors.removeFirst()
        }
        if let error { throw error }
        return Data("attestation".utf8)
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        if let assertionError { throw assertionError }
        lock.withLock { assertedHashes.append(clientDataHash) }
        return Data("assertion".utf8)
    }
}

actor FakeTokens: TokenSource {
    var access: String
    var id: String? = "id.token.here"
    var refreshes = 0
    var refreshFails = false

    init(access: String) {
        self.access = access
    }

    func accessToken() async throws -> String { access }

    func forceRefresh() async throws -> String {
        refreshes += 1
        if refreshFails { throw AuthError.signedOut }
        access = "refreshed-\(refreshes)"
        return access
    }

    func idToken() async -> String? { id }

    func setRefreshFails(_ v: Bool) { refreshFails = v }
}

/// Answers by path, in order; records every request it saw.
final class FakeTransport: HTTPTransport, @unchecked Sendable {
    struct Reply {
        var status: Int
        var json: Any
        var headers: [String: String] = [:]
    }

    var replies: [String: [Reply]] = [:]
    var seen: [URLRequest] = []
    var failNetwork = false
    private let lock = NSLock()

    func on(_ path: String, _ status: Int, _ json: Any, headers: [String: String] = [:]) {
        lock.withLock { replies[path, default: []].append(Reply(status: status, json: json, headers: headers)) }
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let path = request.url!.path
        let reply: Reply? = lock.withLock {
            seen.append(request)
            guard var queue = replies[path], !queue.isEmpty else { return nil }
            let r = queue.count > 1 ? queue.removeFirst() : queue[0]
            replies[path] = queue
            return r
        }
        if failNetwork { throw URLError(.notConnectedToInternet) }
        let r = reply ?? Reply(status: 404, json: ["error": "not found"])
        let data = try JSONSerialization.data(withJSONObject: r.json, options: [.fragmentsAllowed])
        return (data, HTTPURLResponse(url: request.url!, statusCode: r.status, httpVersion: "HTTP/1.1", headerFields: r.headers)!)
    }

    func paths() -> [String] {
        lock.withLock { seen.map { $0.url!.path } }
    }
}

let gateRefusal: [String: Any] = ["error": AppContract.gateRefusalMessage]
let testChallenge = String(repeating: "A", count: 43)
let testChallenge2 = String(repeating: "B", count: 43)
