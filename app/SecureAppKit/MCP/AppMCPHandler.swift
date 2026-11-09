import Foundation

/// The MCP server's protocol: stateless Streamable HTTP, one JSON-RPC message
/// in, one JSON body out, no session and no event stream.
///
/// Pure: the API, the person's confirmation, readiness and the clock-free id
/// source are injected, so it is unit tested without Network.framework. Every
/// tool call reaches the Worker only through `perform`, which is AppClient in
/// the app, so the Worker sees the genuine app and the person's own token.
public struct MCPReply: Equatable, Sendable {
    public var status: Int
    /// nil for the 202 a notification gets.
    public var body: Data?
}

public final class AppMCPHandler: Sendable {
    public static let supportedProtocolVersions = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]
    public static let serverName = "secure-app"
    public static let declined = "The person declined this in Secure App."
    public static let notReady = "Secure App isn't ready. Open Secure App on this Mac, sign in and unlock it, then try again."

    public typealias Perform = @Sendable (AppHTTPRequest) async -> AppResult
    public typealias Confirm = @Sendable (MCPConfirmation) async -> Bool
    public typealias IsReady = @Sendable () async -> Bool

    private let perform: Perform
    private let confirm: Confirm
    private let isReady: IsReady
    private let makeReference: @Sendable () -> String
    private let tools: [MCPTool]

    public init(
        perform: @escaping Perform,
        confirm: @escaping Confirm,
        isReady: @escaping IsReady,
        makeReference: @escaping @Sendable () -> String = { UUID().uuidString },
        tools: [MCPTool] = AppMCPTools.all
    ) {
        self.perform = perform
        self.confirm = confirm
        self.isReady = isReady
        self.makeReference = makeReference
        self.tools = tools
    }

    // MARK: JSON-RPC

    public func handle(_ body: Data) async -> MCPReply {
        let parsed: Any
        do {
            parsed = try JSONSerialization.jsonObject(with: body)
        } catch {
            return MCPReply(status: 400, body: Self.rpcError(nil, -32700, "Parse error"))
        }
        guard let message = parsed as? [String: Any], message["jsonrpc"] as? String == "2.0" else {
            return MCPReply(status: 400, body: Self.rpcError(nil, -32600, "Invalid request"))
        }
        let id = message["id"]
        // A response from the client, or a notification: no body back.
        guard let method = message["method"] as? String else {
            if message["result"] != nil || message["error"] != nil { return MCPReply(status: 202, body: nil) }
            return MCPReply(status: 400, body: Self.rpcError(nil, -32600, "Invalid request"))
        }
        if id == nil { return MCPReply(status: 202, body: nil) }
        let params = message["params"] as? [String: Any] ?? [:]

        switch method {
        case "initialize":
            let requested = params["protocolVersion"] as? String ?? ""
            let version = Self.supportedProtocolVersions.contains(requested) ? requested : Self.supportedProtocolVersions[0]
            return Self.ok(id, [
                "protocolVersion": version,
                "capabilities": ["tools": ["listChanged": false]],
                "serverInfo": ["name": Self.serverName, "title": "Secure App", "version": "1.0.0"],
                "instructions": "These tools call the API through Secure App on this Mac, as the signed-in person. Reads return JSON. Every write is confirmed on screen first, and can be declined.",
            ])
        case "ping":
            return Self.ok(id, [:])
        case "tools/list":
            return Self.ok(id, ["tools": tools.map(Self.descriptor)])
        case "tools/call":
            return Self.ok(id, await call(params))
        default:
            return MCPReply(status: 200, body: Self.rpcError(id, -32601, "Method not found: \(method)"))
        }
    }

    // MARK: tools/call

    private func call(_ params: [String: Any]) async -> [String: Any] {
        let name = params["name"] as? String ?? ""
        let args = params["arguments"] as? [String: Any] ?? [:]
        guard let tool = tools.first(where: { $0.name == name }) else {
            Log.mcp.notice("mcp tool refused, reason: unknown_tool")
            return Self.errorResult("unknown_tool", "There's no tool called \(name).")
        }
        guard await isReady() else {
            Log.mcp.notice("mcp tool refused, reason: not_ready, tool: \(tool.name, privacy: .public)")
            return Self.errorResult("not_ready", Self.notReady)
        }

        let plan: MCPPlan
        do {
            plan = try tool.plan(args, makeReference())
        } catch let MCPArgError.invalid(message) {
            Log.mcp.notice("mcp tool refused, reason: invalid_arguments, tool: \(tool.name, privacy: .public)")
            return Self.errorResult("invalid_arguments", message)
        } catch {
            Log.mcp.error("mcp tool refused, reason: plan_failed, tool: \(tool.name, privacy: .public)")
            return Self.errorResult("internal_error", "That request couldn't be built.")
        }

        if let confirmation = plan.confirmation {
            guard await confirm(confirmation) else {
                Log.mcp.notice("mcp write declined, tool: \(tool.name, privacy: .public)")
                return Self.errorResult("declined", Self.declined)
            }
            // The person may have locked the app while the question was open.
            guard await isReady() else {
                Log.mcp.notice("mcp tool refused, reason: not_ready_after_confirm, tool: \(tool.name, privacy: .public)")
                return Self.errorResult("not_ready", Self.notReady)
            }
        }

        var combined: [String: Any] = [:]
        var single: Any?
        for (key, request) in plan.requests {
            switch await send(request, tool: tool.name) {
            case .success(let value):
                if key.isEmpty { single = value } else { combined[key] = value }
            case .failure(let result):
                return result
            }
        }
        let data: [String: Any] = single.map { $0 as? [String: Any] ?? ["items": $0] } ?? combined
        if !tool.readOnly { Log.mcp.info("mcp write sent, tool: \(tool.name, privacy: .public)") }
        return Self.successResult(data, summary: plan.summary(single ?? combined))
    }

    private enum Sent {
        case success(Any)
        case failure([String: Any])
    }

    private func send(_ request: AppHTTPRequest, tool: String) async -> Sent {
        switch await perform(request) {
        case .failed(let reason):
            Log.mcp.notice("mcp request failed, reason: \(reason, privacy: .public), tool: \(tool, privacy: .public)")
            return .failure(Self.errorResult("request_failed", "Secure App couldn't reach the server (\(reason)). Check Secure App is signed in and online."))
        case .response(let status, _, let body):
            let json = (try? JSONSerialization.jsonObject(with: body, options: [.fragmentsAllowed])) ?? [:]
            guard (200..<300).contains(status) else {
                let message = (json as? [String: Any])?["error"] as? String ?? "The server refused the request."
                Log.mcp.notice("mcp request refused, status: \(status, privacy: .public), tool: \(tool, privacy: .public)")
                return .failure(Self.errorResult("http_\(status)", message, extra: ["status": status]))
            }
            return .success(json)
        }
    }

    // MARK: Shapes

    static func descriptor(_ tool: MCPTool) -> [String: Any] {
        let schema = (try? JSONSerialization.jsonObject(with: Data(tool.inputSchema.utf8))) ?? [:]
        return [
            "name": tool.name,
            "title": tool.title,
            "description": tool.description,
            "inputSchema": schema,
            "annotations": [
                "title": tool.title,
                "readOnlyHint": tool.readOnly,
                "destructiveHint": tool.destructive,
                "openWorldHint": false,
            ],
        ]
    }

    static func successResult(_ data: [String: Any], summary: String) -> [String: Any] {
        let pretty = (try? JSONSerialization.data(withJSONObject: data, options: [.prettyPrinted, .sortedKeys])).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        return ["content": [["type": "text", "text": "\(summary)\n\n\(pretty)"]], "structuredContent": data]
    }

    static func errorResult(_ reason: String, _ message: String, extra: [String: Any] = [:]) -> [String: Any] {
        var structured: [String: Any] = ["error": message, "reason": reason]
        structured.merge(extra) { $1 }
        return ["isError": true, "content": [["type": "text", "text": message]], "structuredContent": structured]
    }

    static func ok(_ id: Any?, _ result: [String: Any]) -> MCPReply {
        MCPReply(status: 200, body: encode(["jsonrpc": "2.0", "id": id ?? NSNull(), "result": result]))
    }

    static func rpcError(_ id: Any?, _ code: Int, _ message: String) -> Data {
        encode(["jsonrpc": "2.0", "id": id ?? NSNull(), "error": ["code": code, "message": message]])
    }

    private static func encode(_ object: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }
}
