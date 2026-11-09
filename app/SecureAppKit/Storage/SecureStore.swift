import Foundation
import Security

/// Small secrets by name: tokens, the App Attest key id. The Keychain in the app,
/// an in-memory fake in tests.
public protocol SecureStore: AnyObject, Sendable {
    func data(for account: String) throws -> Data?
    func set(_ data: Data, for account: String) throws
    func remove(_ account: String) throws
}

public enum SecureStoreError: Error, Equatable {
    case keychain(OSStatus)
}

public extension SecureStore {
    func value<T: Decodable>(_ type: T.Type, for account: String) throws -> T? {
        guard let data = try data(for: account) else { return nil }
        return try JSONDecoder().decode(type, from: data)
    }

    func setValue<T: Encodable>(_ value: T, for account: String) throws {
        try set(JSONEncoder().encode(value), for: account)
    }
}

/// Generic passwords in the data protection keychain, readable only on this Mac
/// (never synced, never in a backup that restores elsewhere) and only after the
/// first unlock since boot: the keychain class kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.
public final class KeychainStore: SecureStore, @unchecked Sendable {
    private let service: String

    public init(service: String) {
        self.service = service
    }

    private func base(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    public func data(for account: String) throws -> Data? {
        var query = base(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw SecureStoreError.keychain(status) }
        return out as? Data
    }

    public func set(_ data: Data, for account: String) throws {
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(base(account) as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw SecureStoreError.keychain(status) }
        var add = base(account)
        add.merge(update) { $1 }
        let added = SecItemAdd(add as CFDictionary, nil)
        guard added == errSecSuccess else { throw SecureStoreError.keychain(added) }
    }

    public func remove(_ account: String) throws {
        let status = SecItemDelete(base(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SecureStoreError.keychain(status) }
    }
}

/// For tests and previews.
public final class InMemorySecureStore: SecureStore, @unchecked Sendable {
    private var items: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func data(for account: String) throws -> Data? {
        lock.withLock { items[account] }
    }

    public func set(_ data: Data, for account: String) throws {
        lock.withLock { items[account] = data }
    }

    public func remove(_ account: String) throws {
        _ = lock.withLock { items.removeValue(forKey: account) }
    }

    public var accounts: [String] {
        lock.withLock { Array(items.keys).sorted() }
    }
}
