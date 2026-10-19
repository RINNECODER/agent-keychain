@testable import AgentKeychainCore
import JavaScriptCore
import XCTest

/// Ported from Axolotl's KeyGrabberTests / MCPBridgeTests.
final class DetectorTests: XCTestCase {
    func testDetectorRule() {
        let mixed = "Q7rT2kLm9XvB4nWc8YpZ3hJd6FsG1aKe5UoR0tIy"     // 40, upper+lower+digits
        let lower = "k3j9x2m7q8w1e4r5t6y0u9i8o7p6a5s4d3f2g1h0"     // 40, lowercase + digits
        let sha = "3f9c2b7e1d4a6c8b9e0f2a1d3c5b7e9f0a2c4e6b"
        let uuid = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
        let positives: [(String, String)] = [
            ("Your new secret key: sk-proj-" + mixed, "known prefix"),
            ("Here it is: " + mixed, "random-looking on its own"),
            ("Access token " + lower, "labeled lowercase token"),
            ("API key: " + uuid, "labeled UUID"),
            ("token: " + sha, "labeled SHA"),
        ]
        for (text, why) in positives {
            XCTAssertEqual(SecretDetector.secretRanges(in: text).count, 1, why)
            XCTAssertTrue(AgentRedaction.redact(text).hasSuffix(AgentRedaction.mask), why)
        }
        let negatives: [(String, String)] = [
            ("Open https://app.test/items/\(uuid)/edit", "UUID in a URL"),
            ("Request id: \(uuid)", "unlabeled UUID"),
            ("Merged commit \(sha) into main", "commit SHA in text"),
            ("<link href=\"/static/main.\(sha.prefix(24)).css\">", "bundle hash"),
            ("class css-1a2b3c4d5e6f7a8b9c0d1e2f", "CSS hash class"),
            ("See https://x.test/cb?token=\(lower)", "token inside a URL query"),
            ("Call getUserAccountSettingsForProfile2 first", "camelCase identifier"),
            ("internationalization_localization_settings", "long word without digits"),
        ]
        for (text, why) in negatives {
            XCTAssertEqual(SecretDetector.secretRanges(in: text).count, 0, why)
            XCTAssertEqual(AgentRedaction.redact(text), text, why)
        }
        XCTAssertEqual(AgentRedaction.redact(lower, label: "Access token"), AgentRedaction.mask)
        XCTAssertEqual(AgentRedaction.redact(lower, label: "Search"), lower)
        XCTAssertEqual(AgentRedaction.redact("token ghp_" + String(repeating: "x", count: 36) + " end"), "token \(AgentRedaction.mask) end")
        XCTAssertEqual(AgentRedaction.redact("sk-short and plain text"), "sk-short and plain text")
    }

    func testURLRedactionMasksSecretsKeepsShape() {
        let url = "https://app.example.com/auth/callback?code=abc123&state=xyz&page=2&q=hello#access_token=eyJhbGciOi"
        let out = AgentRedaction.redactURL(url)
        XCTAssertTrue(out.hasPrefix("https://app.example.com/auth/callback?"), out)
        XCTAssertFalse(out.contains("abc123"), out)
        XCTAssertFalse(out.contains("eyJhbGciOi"), out)
        XCTAssertTrue(out.contains("page=2") && out.contains("q=hello"), out)
        XCTAssertTrue(out.contains("code=REDACTED") && out.contains("state=xyz"), out)
        let flagged = AgentRedaction.redactURL("https://x.example.com/p?blob=sk-proj-" + String(repeating: "a1B2", count: 12))
        XCTAssertFalse(flagged.contains("a1B2a1B2"), flagged)
        XCTAssertEqual(AgentRedaction.redactURL("https://example.com/a/b"), "https://example.com/a/b")
    }

    func testRedactionMasksPathTokensAndLongTokens() {
        let mixed = randomToken(43)
        XCTAssertEqual(AgentRedaction.redactURL("https://accounts.example.com/reset-password/\(mixed)?lang=en"),
                       "https://accounts.example.com/reset-password/REDACTED?lang=en")
        let hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
        XCTAssertEqual(AgentRedaction.redactURL("https://example.com/reset-password/\(hex)"), "https://example.com/reset-password/REDACTED")
        let long = randomToken(300)
        XCTAssertEqual(AgentRedaction.redact("session \(long) end"), "session \(AgentRedaction.mask) end")
        for normal in ["https://github.com/apple/swift/commit/\(hex)", "https://example.com/blog/2024/how-to-write-swift-tests-well",
                       "https://en.wikipedia.org/wiki/Representational_state_transfer"] {
            XCTAssertEqual(AgentRedaction.redactURL(normal), normal)
        }
        let prose = "Internationalization and representational considerations remain"
        XCTAssertEqual(AgentRedaction.redact(prose), prose)
    }

    func testSnapshotIsRedactedBeforeAModelSeesIt() throws {
        let key = "sk-proj-" + randomToken(40)
        let json = """
        {"url":"https://platform.example.com/keys?token=\(randomToken(30))","title":"Keys","text":"Your key: \(key) (keep it safe)",
         "actions":[{"id":"e1","kind":"fill","label":"API key","current_value":"\(randomToken(24, seed: 7).lowercased())1"}],
         "scroll":{"y":0,"height":100},"omitted_actions":0,"marker":"m","node_keys":{},"fingerprint":"f"}
        """
        let out = render(try PageSnapshot.decode(json))
        XCTAssertTrue(out.contains("Your key: \(AgentRedaction.mask) (keep it safe)"), out)
        XCTAssertFalse(out.contains(key), out)
        XCTAssertTrue(out.contains("token=REDACTED"), out)
        XCTAssertTrue(out.contains("e1 [fill] API key = \(AgentRedaction.mask)"), out)
    }

    func testRegistryAndDefaultName() {
        XCTAssertEqual(KeyService.resolve("OpenAI")?.url.absoluteString, "https://platform.openai.com/api-keys")
        XCTAssertEqual(KeyService.resolve("hugging face")?.id, "huggingface")
        XCTAssertEqual(KeyService.resolve("claude")?.id, "anthropic")
        let fallback = KeyService.resolve("example.org")
        XCTAssertEqual(fallback?.known, false)
        XCTAssertEqual(fallback?.id, "example.org")
        XCTAssertEqual(fallback?.url.absoluteString, "https://example.org")
        XCTAssertEqual(KeyService.resolve("acme")?.url.absoluteString, "https://acme.com")
        XCTAssertNil(KeyService.resolve("  "))
        XCTAssertNil(KeyService.resolve("javascript://alert(1)"))
        var c = DateComponents(year: 2026, month: 10, day: 15, hour: 9, minute: 8, second: 7)
        c.calendar = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone.current
        XCTAssertEqual(KeyService.defaultKeyName(c.date!), "agent-20261015-090807")
    }

    /// The capture's save rule: new secret-looking values only; never the key's name or a value already on the page.
    func testCaptureAcceptsOnlyNewSecrets() {
        let key = randomToken(40)
        XCTAssertTrue(SecretCapture.accepts(key, context: "", keyName: "ci", baseline: []))
        XCTAssertFalse(SecretCapture.accepts(key, context: "", keyName: "ci", baseline: [SecretCapture.hash(key)]))
        XCTAssertFalse(SecretCapture.accepts(key, context: "", keyName: key, baseline: []))
        let sha = "3f9c2b7e1d4a6c8b9e0f2a1d3c5b7e9f0a2c4e6b"
        XCTAssertFalse(SecretCapture.accepts(sha, context: "Commit", keyName: "ci", baseline: []))
        XCTAssertTrue(SecretCapture.accepts(sha, context: "Your new token", keyName: "ci", baseline: []))
    }

    /// The in-page candidate regex (run in JavaScriptCore, no web view) finds the same tokens as the Swift detector.
    func testPageRegexMatchesSwiftCandidates() throws {
        let ctx = try XCTUnwrap(JSContext())
        ctx.evaluateScript("const re = \(SecretCapture.candidateRegexJS); function c(t) { return [...t.matchAll(re)].map(m => m[0]); }")
        let samples = [
            "Your key sk-proj-\(randomToken(40)) and id \(randomToken(24, seed: 3))",
            "https://example.com/items/\(randomToken(30))/edit and ?token=\(randomToken(30))",
            "file main.\(randomToken(24)).css, short abc, under_score_token_\(randomToken(20))",
        ]
        for s in samples {
            let js = ctx.objectForKeyedSubscript("c").call(withArguments: [s]).toArray() as? [String]
            XCTAssertNil(ctx.exception, "\(ctx.exception!)")
            XCTAssertEqual(js, SecretDetector.candidates(in: s), s)
        }
        XCTAssertTrue(SecretCapture.scanScript.contains(SecretCapture.candidateRegexJS))
    }
}
