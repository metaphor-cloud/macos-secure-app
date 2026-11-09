import Foundation
import Network
import SecureAppKit

/// The MCP listener: HTTP/1.1 on 127.0.0.1 only, POST /mcp,
/// one request per connection. What it will answer is decided by MCPHTTPGuard
/// (secret, Origin, Host); what a tool does is AppMCPHandler's.
final class LocalMCPServer: @unchecked Sendable {
    static let defaultPort: UInt16 = 47821

    let port: UInt16
    private let handler: AppMCPHandler
    private let secret: @Sendable () -> String?
    private let queue = DispatchQueue(label: "com.example.secureapp.mcp")
    private var listener: NWListener?

    /// Called on the main queue when the listener fails or stops being ready.
    var onState: (@Sendable (_ listening: Bool, _ error: String?) -> Void)?

    init(port: UInt16 = LocalMCPServer.defaultPort, handler: AppMCPHandler, secret: @escaping @Sendable () -> String?) {
        self.port = port
        self.handler = handler
        self.secret = secret
    }

    func start() {
        guard listener == nil, let nwPort = NWEndpoint.Port(rawValue: port) else { return }
        let parameters = NWParameters.tcp
        // Loopback only: bound to 127.0.0.1, never 0.0.0.0, so nothing off this Mac can connect.
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: nwPort)
        parameters.allowLocalEndpointReuse = true
        do {
            let listener = try NWListener(using: parameters)
            listener.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    Log.mcp.info("mcp server listening, port: \(self?.port ?? 0, privacy: .public)")
                    self?.report(true, nil)
                case .failed(let error):
                    Log.mcp.error("mcp server failed, code: \(String(describing: error).prefix(60), privacy: .public)")
                    self?.stop()
                    self?.report(false, "Couldn't listen on port \(self?.port ?? 0). Another app may be using it.")
                case .cancelled:
                    break
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
            self.listener = listener
            listener.start(queue: queue)
        } catch {
            Log.mcp.error("mcp server not started, reason: listener_error")
            report(false, "Couldn't listen on port \(port). Another app may be using it.")
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        Log.mcp.info("mcp server stopped")
    }

    private func report(_ listening: Bool, _ error: String?) {
        let onState = onState
        DispatchQueue.main.async { onState?(listening, error) }
    }

    // MARK: Connections

    private func accept(_ connection: NWConnection) {
        connection.start(queue: queue)
        // A client that connects and goes quiet doesn't hold a slot: tool calls wait on the person's
        // confirmation after the request is read, so this covers reading only.
        let deadline = DispatchWorkItem { connection.cancel() }
        queue.asyncAfter(deadline: .now() + 15, execute: deadline)
        read(connection, buffer: Data(), deadline: deadline)
    }

    private func read(_ connection: NWConnection, buffer: Data, deadline: DispatchWorkItem) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return connection.cancel() }
            var buffer = buffer
            if let data { buffer.append(data) }
            if error != nil { return connection.cancel() }

            guard let (head, consumed) = MCPHTTPHead.parse(buffer) else {
                if buffer.count > MCPHTTPGuard.maxHeadBytes {
                    return self.refuse(.badRequest, connection)
                }
                if isComplete { return connection.cancel() }
                return self.read(connection, buffer: buffer, deadline: deadline)
            }
            guard let secret = self.secret() else {
                Log.mcp.error("mcp request refused, reason: no_secret")
                return self.refuse(.unauthorised, connection)
            }
            if let refusal = MCPHTTPGuard.check(head, port: self.port, secret: secret) {
                return self.refuse(refusal, connection)
            }
            self.readBody(connection, head: head, buffer: Data(buffer.dropFirst(consumed)), deadline: deadline)
        }
    }

    private func readBody(_ connection: NWConnection, head: MCPHTTPHead, buffer: Data, deadline: DispatchWorkItem) {
        let length = head.contentLength ?? 0
        if buffer.count >= length {
            deadline.cancel()
            let body = Data(buffer.prefix(length))
            Task {
                let reply = await self.handler.handle(body)
                self.respond(connection, status: reply.status, body: reply.body)
            }
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self, error == nil else { return connection.cancel() }
            var buffer = buffer
            if let data { buffer.append(data) }
            if isComplete && buffer.count < length { return connection.cancel() }
            self.readBody(connection, head: head, buffer: buffer, deadline: deadline)
        }
    }

    // MARK: Answers

    private func refuse(_ refusal: MCPHTTPRefusal, _ connection: NWConnection) {
        Log.mcp.notice("mcp request refused, reason: \(refusal.rawValue, privacy: .public)")
        var headers: [String: String] = [:]
        if refusal == .methodNotAllowed { headers["Allow"] = "POST" }
        if refusal == .unauthorised { headers["WWW-Authenticate"] = "Bearer" }
        let message = Data("{\"error\":\"\(refusal.rawValue)\"}".utf8)
        respond(connection, status: refusal.status, body: message, extraHeaders: headers)
    }

    private func respond(_ connection: NWConnection, status: Int, body: Data?, extraHeaders: [String: String] = [:]) {
        var head = "HTTP/1.1 \(status) \(Self.reason(status))\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: \(body?.count ?? 0)\r\n"
        if body != nil { head += "Content-Type: application/json\r\n" }
        for (name, value) in extraHeaders { head += "\(name): \(value)\r\n" }
        head += "\r\n"
        var out = Data(head.utf8)
        if let body { out.append(body) }
        connection.send(content: out, completion: .contentProcessed { _ in connection.cancel() })
    }

    private static func reason(_ status: Int) -> String {
        switch status {
        case 200: "OK"
        case 202: "Accepted"
        case 400: "Bad Request"
        case 401: "Unauthorized"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 405: "Method Not Allowed"
        case 411: "Length Required"
        case 413: "Content Too Large"
        default: "Error"
        }
    }
}
