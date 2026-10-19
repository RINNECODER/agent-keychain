import Foundation
import Security

/// Raw storage for key values, behind a protocol so tests never touch the real Keychain.
public protocol SecretStore: AnyObject {
    /// errSecSuccess, errSecDuplicateItem, or another failure.
    func add(account: String, value: Data) -> OSStatus
    func items() -> [Vault.Item]
    func read(account: String) -> Data?
    func delete(account: String) -> OSStatus
}

/// Generic passwords in the login keychain, service "agent-keychain".
/// shortcut: the data protection keychain needs a signed keychain-access-groups entitlement, which a
/// `swift build` binary does not have; upgrade when the tool ships as a signed app.
/// The login keychain is never synced to iCloud, and each item's ACL trusts only this binary,
/// so any other process (`security find-generic-password`, a rebuilt binary) gets a macOS prompt.
public final class KeychainSecretStore: SecretStore {
    let service: String
    public init(service: String = Vault.defaultService) { self.service = service }

    private func base(_ account: String? = nil) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        if let account { q[kSecAttrAccount as String] = account }
        return q
    }

    public func add(account: String, value: Data) -> OSStatus {
        var q = base(account)
        q[kSecValueData as String] = value
        q[kSecAttrLabel as String] = "\(service): \(account)"
        q[kSecAttrDescription as String] = "API key saved by agent-keychain"
        return SecItemAdd(q as CFDictionary, nil)
    }

    public func items() -> [Vault.Item] {
        var q = base()
        q[kSecReturnAttributes as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess,
              let rows = result as? [[String: Any]] else { return [] }
        return rows.compactMap { attrs in
            (attrs[kSecAttrAccount as String] as? String).map {
                Vault.Item(name: $0, created: attrs[kSecAttrCreationDate as String] as? Date)
            }
        }
    }

    public func read(account: String) -> Data? {
        var q = base(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    public func delete(account: String) -> OSStatus {
        SecItemDelete(base(account) as CFDictionary)
    }
}

/// Where grabbed keys live: account "<service>/<key name>". Callers outside the package get only
/// names; `value(_:)` is internal and used only to inject a key into a child process.
public final class Vault {
    public static let defaultService = "agent-keychain"

    public struct Item: Equatable {
        public let name: String
        public let created: Date?
    }

    public enum VaultError: LocalizedError {
        case keychain(OSStatus)
        case notFound(String)
        public var errorDescription: String? {
            switch self {
            case .keychain(let s): return "Keychain error \(s)."
            case .notFound(let n): return "No key named \(n). Use list_keys."
            }
        }
    }

    let store: SecretStore
    public init(store: SecretStore = KeychainSecretStore()) { self.store = store }

    /// Saves under a new name and returns it. An existing name is never overwritten: it gets `-2`, `-3`… instead.
    @discardableResult
    func store(_ value: String, account requested: String) throws -> String {
        let data = Data(value.utf8)
        var account = requested
        var suffix = 1
        while true {
            let status = store.add(account: account, value: data)
            if status == errSecSuccess { return account }
            guard status == errSecDuplicateItem, suffix < 1000 else { throw VaultError.keychain(status) }
            suffix += 1
            account = "\(requested)-\(suffix)"
        }
    }

    /// Saved keys without their values, newest first.
    public func items() -> [Item] {
        store.items().sorted { ($0.created ?? .distantPast) > ($1.created ?? .distantPast) }
    }

    func value(_ name: String) -> String? {
        store.read(account: name).flatMap { String(data: $0, encoding: .utf8) }
    }

    func delete(_ name: String) throws {
        let status = store.delete(account: name)
        if status == errSecItemNotFound { throw VaultError.notFound(name) }
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
    }
}
