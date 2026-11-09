import os

/// One subsystem, a category per area, so Console can filter on either.
/// Never log tokens, assertions, attestations, keys or request bodies: key ids
/// are logged as their first 12 characters (keyRef), as the Worker does.
public enum Log {
    public static let subsystem = "com.example.secureapp"
    public static let app = Logger(subsystem: subsystem, category: "app")
    public static let auth = Logger(subsystem: subsystem, category: "auth")
    public static let attest = Logger(subsystem: subsystem, category: "attest")
    public static let api = Logger(subsystem: subsystem, category: "api")
    public static let bridge = Logger(subsystem: subsystem, category: "bridge")
    public static let web = Logger(subsystem: subsystem, category: "web")
    public static let live = Logger(subsystem: subsystem, category: "live")
    public static let lock = Logger(subsystem: subsystem, category: "lock")
    /// The local MCP server. Reason codes and tool names only: never the secret, arguments or note text.
    public static let mcp = Logger(subsystem: subsystem, category: "mcp")
}

/// The first 12 characters of a key id, as the Worker's logs show it.
public func keyRef(_ keyId: String) -> String {
    String(keyId.prefix(12))
}
