// Ported from browser-use/jev-ultrafast (MIT License, Copyright (c) 2026 Browser Use):
// jev_ultrafast/questions.py and action_space() in jev_ultrafast/model.py.

import CryptoKit
import Foundation

// MARK: - JSON

/// Minimal JSON value used for MCP messages and tool results.
/// Objects encode with sorted keys (see `JSONValue.encoder`), so bodies are deterministic.
public enum JSONValue: Codable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case null
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        // Numbers before Bool so a probability of 0 or 1 never reads as a boolean.
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode([JSONValue].self) { self = .array(v) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .bool(let v): try c.encode(v)
        case .null: try c.encodeNil()
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }

    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var numberValue: Double? { if case .number(let n) = self { return n }; return nil }
    public var objectValue: [String: JSONValue]? { if case .object(let o) = self { return o }; return nil }

    static var encoder: JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }

    public func jsonString() -> String {
        (try? String(data: Self.encoder.encode(self), encoding: .utf8)) ?? "null"
    }
}

extension JSONValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
}

// MARK: - Page model

/// One observed action. `node` is a code-owned id from the page script's WeakMap,
/// never a model-generated selector.
struct PageAction: Codable, Equatable {
    var id: String
    var kind: String          // click | fill | select | scroll | wait
    var label: String
    var node: Int?
    var role: String?
    var value: String?
    var currentValue: String?
    var checked: String?
    var selected: String?
    var expanded: String?
    var delta: Double?

    enum CodingKeys: String, CodingKey {
        case id, kind, label, node, role, value, checked, selected, expanded, delta
        case currentValue = "current_value"
    }

    /// Arguments for the page script (`A.act`, `A.settle`).
    var scriptArgument: [String: Any] {
        var d: [String: Any] = ["id": id, "kind": kind]
        if let node { d["node"] = node }
        if let value { d["value"] = value }
        if let delta { d["delta"] = delta }
        return d
    }
}

struct PageSnapshot: Codable, Equatable {
    struct Scroll: Codable, Equatable { var y: Double; var height: Double }

    var url: String
    var title: String
    var text: String
    var actions: [PageAction]
    var scroll: Scroll
    var omittedActions: Int
    /// Opaque page marker; compared for freshness before DONE/BLOCKED/fill/scroll.
    var marker: String
    /// Per-node page key + guard; compared for freshness before click/select.
    var nodeKeys: [String: String]
    /// SHA-256 of url/text/actions/scroll; used for `page_changed`.
    var fingerprint: String

    enum CodingKeys: String, CodingKey {
        case url, title, text, actions, scroll, marker, fingerprint
        case omittedActions = "omitted_actions"
        case nodeKeys = "node_keys"
    }

    func action(id: String) -> PageAction? { actions.first { $0.id == id } }

    /// Decodes the page script's JSON, hashes the fingerprint and runs `redact`.
    static func decode(_ json: String) throws -> PageSnapshot {
        var s = try JSONDecoder().decode(PageSnapshot.self, from: Data(json.utf8))
        s.fingerprint = SHA256.hash(data: Data(s.fingerprint.utf8)).map { String(format: "%02x", $0) }.joined()
        return AgentRedaction.redact(s)
    }
}

/// Single place where page content or process output leaves for a model (an
/// outside agent over MCP). Masks well-known API key and token formats, plus generic
/// random-looking keys (see `SecretDetector` for the rule), so a page that shows a secret
/// never hands it to a model. Freshness markers are computed in the page and untouched.
enum AgentRedaction {
    static let mask = "[redacted secret]"

    static let knownFormats = [
        #"\bsk-[A-Za-z0-9_-]{20,}"#,                                   // OpenAI / Anthropic
        #"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"#,             // Stripe
        #"\bgh[pousr]_[A-Za-z0-9]{30,}"#, #"\bgithub_pat_[A-Za-z0-9_]{30,}"#,
        #"\bAKIA[0-9A-Z]{16}\b"#,                                     // AWS access key id
        #"\bAIza[0-9A-Za-z_-]{35}"#,                                   // Google
        #"\bxox[abposr]-[A-Za-z0-9-]{10,}"#,                           // Slack
        #"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"#, // JWT
        #"\bhf_[A-Za-z0-9]{30,}"#,                                     // Hugging Face
        #"\br8_[A-Za-z0-9]{30,}"#,                                     // Replicate
        #"\bgsk_[A-Za-z0-9]{30,}"#,                                    // Groq
    ]

    private static let secretPattern: NSRegularExpression? = try? NSRegularExpression(pattern: knownFormats.joined(separator: "|"))

    /// `label` is context for a lone value (a field's label), so a token under "API token" is masked.
    static func redact(_ text: String, label: String = "") -> String {
        guard let secretPattern, !text.isEmpty else { return text }
        var out = secretPattern.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text),
                                                         withTemplate: mask)
        for range in SecretDetector.secretRanges(in: out, label: label).reversed() {
            out.replaceSubrange(range, with: mask)
        }
        return out
    }

    private static let sensitiveParam = try? NSRegularExpression(
        pattern: "code|token|key|secret|sig|signature|auth|session|password|passwd|pwd|credential",
        options: .caseInsensitive)

    /// Keeps scheme and host; masks path segments, the fragment and query values that look secret
    /// (sensitive parameter names, or values the detector flags). Parameter names stay.
    static func redactURL(_ urlString: String) -> String {
        guard !urlString.isEmpty, var parts = URLComponents(string: urlString) else { return redact(urlString) }
        func sensitive(_ name: String) -> Bool {
            sensitiveParam?.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)) != nil
        }
        func flagged(_ value: String, _ name: String) -> Bool {
            sensitive(name) || redact(value, label: name) != value
        }
        if let items = parts.percentEncodedQueryItems {
            parts.percentEncodedQueryItems = items.map { item in
                guard let value = item.value, !value.isEmpty else { return item }
                let decoded = value.removingPercentEncoding ?? value
                return flagged(decoded, item.name) ? URLQueryItem(name: item.name, value: "REDACTED") : item
            }
        }
        // Reset-password and magic links carry the token as a path segment; the segment before it is its label.
        var previous = ""
        parts.percentEncodedPath = parts.percentEncodedPath.split(separator: "/", omittingEmptySubsequences: false).map { raw in
            let segment = String(raw)
            let decoded = segment.removingPercentEncoding ?? segment
            defer { previous = decoded }
            return redact(decoded, label: previous) != decoded ? "REDACTED" : segment
        }.joined(separator: "/")
        // A fragment is often an OAuth/magic-link payload (#access_token=…); drop it entirely.
        if let fragment = parts.fragment, !fragment.isEmpty { parts.fragment = "REDACTED" }
        parts.user = nil
        parts.password = nil
        return redact(parts.string ?? urlString)
    }

    static func redact(_ snapshot: PageSnapshot) -> PageSnapshot {
        var s = snapshot
        s.url = redactURL(s.url)
        s.title = redact(s.title)
        s.text = redact(s.text)
        s.actions = s.actions.map { a in
            var a = a
            let label = a.label
            a.label = redact(a.label)
            a.value = a.value.map { redact($0, label: label) }
            a.currentValue = a.currentValue.map { redact($0, label: label) }
            return a
        }
        return s
    }
}

enum AgentError: LocalizedError, Equatable {
    /// The page changed since the snapshot. Observe again; nothing was executed.
    case stalePage(String)
    /// A dropdown change could not be confirmed; inspect before retrying.
    case unconfirmed(String)
    case noText(String)

    var errorDescription: String? {
        switch self {
        case .stalePage(let m), .unconfirmed(let m), .noText(let m): return m
        }
    }
}
