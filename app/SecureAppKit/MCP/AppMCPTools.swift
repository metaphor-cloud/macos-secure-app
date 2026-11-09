import Foundation

/// The MCP tools: each is a declarative entry that turns validated arguments
/// into API requests. Nothing here sends anything; AppMCPHandler sends through
/// AppClient, so every call is signed by the attested key with the signed-in
/// person's own token.
///
/// These three run against the example notes API. Add a tool for each business
/// endpoint worth giving an AI app: a read-only one needs no confirmation, and
/// anything that changes data sets `confirmation` so the person is asked first.

public enum MCPArgError: Error, Equatable {
    case invalid(String)
}

/// What the person is shown before a write goes out.
public struct MCPConfirmation: Equatable, Sendable {
    public var title: String
    /// Plain lines: what, and the exact text.
    public var detail: String
    public var destructive: Bool
}

public struct MCPPlan: Sendable {
    /// One request per key; the result object holds each response under its key.
    /// A single request with the key "" returns its body as is.
    public var requests: [(key: String, request: AppHTTPRequest)]
    /// Set for a write: the person is asked before anything is sent.
    public var confirmation: MCPConfirmation?
    public var summary: @Sendable (Any) -> String
}

public struct MCPTool: Sendable {
    public let name: String
    public let title: String
    public let description: String
    /// JSON Schema, as JSON text.
    public let inputSchema: String
    public let readOnly: Bool
    public let destructive: Bool
    /// `reference` is one fresh id per call, for a write whose API takes an idempotency key.
    public let plan: @Sendable ([String: Any], String) throws -> MCPPlan
}

// MARK: Argument validation

public enum MCPArgs {
    /// Ids reach a path segment, so only the characters ids are made of, and never "." or "/".
    public static func id(_ args: [String: Any], _ name: String) throws -> String {
        guard let value = args[name] as? String, value.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil else {
            throw MCPArgError.invalid("\(name) isn't a valid id.")
        }
        return value
    }

    public static func string(_ args: [String: Any], _ name: String, max: Int) throws -> String {
        guard let raw = args[name] as? String else { throw MCPArgError.invalid("\(name) is required.") }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { throw MCPArgError.invalid("\(name) is required.") }
        guard value.count <= max else { throw MCPArgError.invalid("\(name) is too long. Keep it under \(max) characters.") }
        return value
    }

    public static func optionalString(_ args: [String: Any], _ name: String, max: Int) throws -> String? {
        guard let raw = args[name], !(raw is NSNull) else { return nil }
        guard let text = raw as? String else { throw MCPArgError.invalid("\(name) must be a string.") }
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.isEmpty { return nil }
        guard value.count <= max else { throw MCPArgError.invalid("\(name) is too long. Keep it under \(max) characters.") }
        return value
    }

    public static func oneOf(_ args: [String: Any], _ name: String, _ allowed: [String], default fallback: String) throws -> String {
        guard let raw = args[name], !(raw is NSNull) else { return fallback }
        guard let value = raw as? String, allowed.contains(value) else {
            throw MCPArgError.invalid("\(name) must be one of: \(allowed.joined(separator: ", ")).")
        }
        return value
    }

    /// Unreserved characters only, so a search term can't add a parameter or end the query.
    public static func queryValue(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }
}

// MARK: The table

public enum AppMCPTools {
    public static let maxTitleChars = 120
    public static let maxBodyChars = 10_000

    private static func get(_ path: String) -> AppHTTPRequest {
        AppHTTPRequest(method: "GET", pathAndQuery: path, headers: ["Accept": "application/json"])
    }

    private static func post(_ path: String, _ body: [String: Any]) throws -> AppHTTPRequest {
        let data = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        return AppHTTPRequest(method: "POST", pathAndQuery: path, headers: ["Content-Type": "application/json", "Accept": "application/json"], body: data)
    }

    public static let all: [MCPTool] = [
        MCPTool(
            name: "get_me",
            title: "Who is signed in",
            description: "The person Secure App is signed in as.",
            inputSchema: #"{"type":"object","properties":{},"additionalProperties":false}"#,
            readOnly: true, destructive: false,
            plan: { _, _ in MCPPlan(requests: [("", get("/api/me"))], summary: { _ in "Signed-in account." }) }
        ),
        MCPTool(
            name: "list_notes",
            title: "List notes",
            description: "The notes in the example notes API, newest first, with their author and date.",
            inputSchema: #"{"type":"object","properties":{},"additionalProperties":false}"#,
            readOnly: true, destructive: false,
            plan: { _, _ in
                MCPPlan(requests: [("", get("/api/notes"))], summary: { any in
                    guard let list = (any as? [String: Any])?["notes"] as? [Any] else { return "Done." }
                    return list.isEmpty ? "No notes." : "\(list.count) note\(list.count == 1 ? "" : "s")."
                })
            }
        ),
        MCPTool(
            name: "create_note",
            title: "Create a note",
            description: "Add a note. The person confirms the exact text in Secure App first.",
            inputSchema: #"{"type":"object","properties":{"title":{"type":"string","maxLength":120},"body":{"type":"string","maxLength":10000,"description":"The note, in plain text"}},"required":["title"],"additionalProperties":false}"#,
            readOnly: false, destructive: false,
            plan: { args, _ in
                let title = try MCPArgs.string(args, "title", max: AppMCPTools.maxTitleChars)
                let body = try MCPArgs.optionalString(args, "body", max: AppMCPTools.maxBodyChars) ?? ""
                return MCPPlan(
                    requests: [("", try post("/api/notes", ["title": title, "body": body]))],
                    confirmation: MCPConfirmation(title: "Add this note?", detail: body.isEmpty ? "Title: \(title)" : "Title: \(title)\n\n\(body)", destructive: false),
                    summary: { _ in "Note added." }
                )
            }
        ),
    ]
}
