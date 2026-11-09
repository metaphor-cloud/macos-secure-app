import Foundation
import SecureAppKit

/// The live socket (GET /api/live), opened natively: the page asks for it with
/// {kind: "live", on}, and changes arrive as "live" events. The upgrade request
/// is signed like any other request and holds the signing gate until the
/// handshake finishes, so counters stay in order. Reconnects with a 1s backoff
/// that doubles up to 30s.
@MainActor
final class LiveSocket: NSObject {
    private let client: AppClient
    private let push: ([String: Any]) -> Void
    private let session: URLSession
    private let delegate = HandshakeDelegate()
    private var task: URLSessionWebSocketTask?
    private var wanted = false
    private var attempt = 0
    private var retry: Task<Void, Never>?
    private var generation = 0

    init(client: AppClient, push: @escaping ([String: Any]) -> Void) {
        self.client = client
        self.push = push
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }

    static func reconnectDelay(attempt: Int) -> TimeInterval {
        min(pow(2, Double(attempt)), 30)
    }

    func set(on: Bool) {
        if on {
            guard !wanted else { return }
            wanted = true
            attempt = 0
            connect()
        } else {
            stop()
        }
    }

    func stop() {
        wanted = false
        generation += 1
        retry?.cancel()
        retry = nil
        task?.cancel(with: .normalClosure, reason: nil)
        task = nil
    }

    private func connect() {
        generation += 1
        let gen = generation
        let session = self.session
        let delegate = self.delegate
        Task {
            let opened = OpenedBox()
            let result = await client.performSigned(AppHTTPRequest(method: "GET", pathAndQuery: AppContract.livePath)) { signed in
                var request = signed
                if let url = request.url, var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) {
                    parts.scheme = parts.scheme == "http" ? "ws" : "wss"
                    request.url = parts.url
                }
                let task = session.webSocketTask(with: request)
                let response = try await delegate.handshake(task)
                if response.statusCode == 101 { opened.set(task) }
                return (response.statusCode == 403 ? Self.gateRefusalBody : Data(), response)
            }
            await MainActor.run { self.handshakeFinished(result, task: opened.get(), generation: gen) }
        }
    }

    /// A refused upgrade has no readable body. The live route itself answers 401, never 403,
    /// so a 403 here is the gate, and is recovered as one.
    nonisolated static let gateRefusalBody = (try? JSONSerialization.data(withJSONObject: ["error": AppContract.gateRefusalMessage])) ?? Data()

    private func handshakeFinished(_ result: AppResult, task opened: URLSessionWebSocketTask?, generation gen: Int) {
        guard gen == generation, wanted else {
            opened?.cancel(with: .normalClosure, reason: nil)
            return
        }
        if case .response(101, _, _) = result, let opened {
            task = opened
            attempt = 0
            Log.live.info("live socket connected")
            push(["type": "liveState", "connected": true])
            receive(opened, generation: gen)
        } else {
            let status: String
            switch result {
            case .response(let s, _, _): status = String(s)
            case .failed(let reason): status = reason
            }
            Log.live.notice("live socket did not connect, status: \(status, privacy: .public)")
            scheduleReconnect()
        }
    }

    private func receive(_ socket: URLSessionWebSocketTask, generation gen: Int) {
        socket.receive { [weak self] result in
            Task { @MainActor in
                guard let self, gen == self.generation else { return }
                switch result {
                case .success(let message):
                    switch message {
                    case .string(let text): self.push(["type": "live", "data": text])
                    case .data(let data): self.push(["type": "live", "data": String(decoding: data, as: UTF8.self)])
                    @unknown default: break
                    }
                    self.receive(socket, generation: gen)
                case .failure:
                    // 4403 is a revoke: the reconnect's signed handshake is refused and recovery takes over.
                    Log.live.notice("live socket closed, code: \(socket.closeCode.rawValue, privacy: .public)")
                    self.task = nil
                    self.push(["type": "liveState", "connected": false])
                    self.scheduleReconnect()
                }
            }
        }
    }

    private func scheduleReconnect() {
        guard wanted else { return }
        let delay = Self.reconnectDelay(attempt: attempt)
        attempt += 1
        retry?.cancel()
        retry = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await MainActor.run { if self?.wanted == true { self?.connect() } }
        }
    }
}

/// Resolves when a socket's handshake has finished, with the upgrade response.
private final class HandshakeDelegate: NSObject, URLSessionWebSocketDelegate, @unchecked Sendable {
    private var waiting: [Int: CheckedContinuation<HTTPURLResponse, Error>] = [:]
    private let lock = NSLock()

    func handshake(_ task: URLSessionWebSocketTask) async throws -> HTTPURLResponse {
        try await withCheckedThrowingContinuation { continuation in
            lock.withLock { waiting[task.taskIdentifier] = continuation }
            task.resume()
        }
    }

    private func finish(_ task: URLSessionTask, _ result: Result<HTTPURLResponse, Error>) {
        let continuation = lock.withLock { waiting.removeValue(forKey: task.taskIdentifier) }
        continuation?.resume(with: result)
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        let response = (webSocketTask.response as? HTTPURLResponse)
            ?? HTTPURLResponse(url: webSocketTask.originalRequest!.url!, statusCode: 101, httpVersion: "HTTP/1.1", headerFields: nil)!
        finish(webSocketTask, .success(response))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let response = task.response as? HTTPURLResponse, response.statusCode != 101 {
            finish(task, .success(response))
        } else {
            finish(task, .failure(error ?? URLError(.networkConnectionLost)))
        }
    }
}

private final class OpenedBox: @unchecked Sendable {
    private var task: URLSessionWebSocketTask?
    private let lock = NSLock()
    func set(_ t: URLSessionWebSocketTask) { lock.withLock { task = t } }
    func get() -> URLSessionWebSocketTask? { lock.withLock { task } }
}
