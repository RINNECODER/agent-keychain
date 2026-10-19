@testable import AgentKeychainCore
import Foundation
import Security

final class MemoryStore: SecretStore {
    var rows: [String: (Data, Date)] = [:]
    private var tick = 0.0

    func add(account: String, value: Data) -> OSStatus {
        guard rows[account] == nil else { return errSecDuplicateItem }
        tick += 1
        rows[account] = (value, Date(timeIntervalSince1970: 1_800_000_000 + tick))
        return errSecSuccess
    }
    func items() -> [Vault.Item] { rows.map { Vault.Item(name: $0.key, created: $0.value.1) } }
    func read(account: String) -> Data? { rows[account]?.0 }
    func delete(account: String) -> OSStatus { rows.removeValue(forKey: account) == nil ? errSecItemNotFound : errSecSuccess }
}

final class FakeApprover: Approver {
    var answer = true
    private(set) var reasons: [String] = []
    func approve(reason: String) async -> Bool {
        reasons.append(reason)
        return answer
    }
}

final class FakeGrabber: Grabbing {
    private(set) var grabs: [(String, String?, TimeInterval)] = []
    func grab(service: String, name: String?, wait: TimeInterval) async throws -> JSONValue {
        grabs.append((service, name, wait))
        return ["status": "saved", "saved": .string("\(service)/\(name ?? "x")")]
    }
    func snapshot() async throws -> String { throw AgentError.stalePage("No grab window is open. Call grab_key first.") }
    func click(_ ref: String) async throws -> String { "clicked \(ref)" }
    func type(_ ref: String, text: String) async throws -> String { "typed \(ref)" }
    func scroll(down: Bool) async throws -> String { "scrolled" }
}

/// Deterministic random-looking token (no real key anywhere in the tests).
func randomToken(_ count: Int, seed start: UInt64 = 0x9E3779B97F4A7C15) -> String {
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    var seed = start
    return String((0..<count).map { _ in
        seed = seed &* 6364136223846793005 &+ 1442695040888963407
        return alphabet[Int(seed >> 33) % alphabet.count]
    })
}
