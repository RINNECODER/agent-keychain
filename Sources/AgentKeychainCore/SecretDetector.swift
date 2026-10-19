import Foundation

/// Decides whether a string on a page is an API key or token.
///
/// The rule (shared by `AgentRedaction` and the key grabber):
/// 1. Candidates are runs of `[A-Za-z0-9_-]` of 20–4096 characters that are not part of a URL,
///    path or file name (not preceded by `/ = . ? & # % @` and not followed by `/`).
/// 2. A candidate is a secret when it
///    - starts with a well-known key prefix (`AgentRedaction`'s list: sk-, Stripe, GitHub, AWS, …), or
///    - looks random on its own: 32+ characters with upper case, lower case and digits and
///      ≥ 4 bits of entropy per character (camelCase words and hex hashes do not qualify), or
///    - looks random enough (letters and digits, ≥ 3 bits per character) and sits next to a
///      label such as "key", "token", "secret", "credential", "bearer" or "password".
/// So a commit SHA, a UUID or a CSS/bundle hash in ordinary text is left alone, but the same
/// string under "Your API token" is treated as a secret.
enum SecretDetector {
    /// Characters before which a token is part of a URL, path, query or file name.
    static let candidatePattern = try! NSRegularExpression(
        pattern: #"(?<![A-Za-z0-9_\-/=.?&#%@])[A-Za-z0-9_\-]{20,4096}(?![A-Za-z0-9_\-/])"#)
    static let labelPattern = try! NSRegularExpression(
        pattern: #"(?i)\b(api[\s_-]?keys?|keys?|tokens?|secrets?|credentials?|bearer|passwords?|pat)\b"#)
    static let knownPrefixPattern = try! NSRegularExpression(pattern: "^(?:" + AgentRedaction.knownFormats.joined(separator: "|") + ")")

    /// How many characters before a candidate count as its label in running text.
    static let labelWindow = 48

    static func entropy(_ s: String) -> Double {
        var counts: [Character: Int] = [:]
        for c in s { counts[c, default: 0] += 1 }
        let n = Double(s.count)
        return counts.values.reduce(0) { acc, k in
            let p = Double(k) / n
            return acc - p * log2(p)
        }
    }

    static func hasKnownPrefix(_ s: String) -> Bool {
        knownPrefixPattern.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }

    static func looksRandom(_ s: String) -> Bool {
        s.count >= 32 && s.contains(where: \.isUppercase) && s.contains(where: \.isLowercase) &&
            s.contains(where: \.isNumber) && entropy(s) >= 4.0
    }

    static func looksRandomEnough(_ s: String) -> Bool {
        s.count >= 20 && s.contains(where: \.isLetter) && s.contains(where: \.isNumber) && entropy(s) >= 3.0
    }

    static func isLabel(_ context: String) -> Bool {
        labelPattern.firstMatch(in: context, range: NSRange(context.startIndex..., in: context)) != nil
    }

    /// `candidate` is one token; `context` is the text around it (a field label, a heading).
    static func isSecret(_ candidate: String, context: String) -> Bool {
        hasKnownPrefix(candidate) || looksRandom(candidate) || (looksRandomEnough(candidate) && isLabel(context))
    }

    /// Ranges of secrets in running text. `label` is extra context for every token (a field's label).
    static func secretRanges(in text: String, label: String = "") -> [Range<String.Index>] {
        guard text.count >= 20 else { return [] }
        return candidatePattern.matches(in: text, range: NSRange(text.startIndex..., in: text)).compactMap { m -> Range<String.Index>? in
            guard let range = Range(m.range, in: text) else { return nil }
            let start = text.index(range.lowerBound, offsetBy: -labelWindow, limitedBy: text.startIndex) ?? text.startIndex
            return isSecret(String(text[range]), context: label + " " + text[start..<range.lowerBound]) ? range : nil
        }
    }

    /// Every candidate token in `text`, secret or not.
    static func candidates(in text: String) -> [String] {
        candidatePattern.matches(in: text, range: NSRange(text.startIndex..., in: text))
            .compactMap { Range($0.range, in: text).map { String(text[$0]) } }
    }
}
