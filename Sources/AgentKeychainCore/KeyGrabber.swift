import AppKit
import CryptoKit
import Foundation
import WebKit

// MARK: - Known key dashboards

/// A service whose API-key page is known. Anything else falls back to the site's home page.
public struct KeyService: Equatable {
    public let id: String
    public let name: String
    public let url: URL
    var aliases: [String] = []
    var known = true

    static let registry: [KeyService] = [
        KeyService(id: "openai", name: "OpenAI", url: URL(string: "https://platform.openai.com/api-keys")!, aliases: ["chatgpt", "gpt"]),
        KeyService(id: "anthropic", name: "Anthropic", url: URL(string: "https://platform.claude.com/settings/keys")!, aliases: ["claude"]),
        KeyService(id: "google-ai-studio", name: "Google AI Studio", url: URL(string: "https://aistudio.google.com/apikey")!, aliases: ["gemini", "google", "aistudio"]),
        KeyService(id: "github", name: "GitHub", url: URL(string: "https://github.com/settings/personal-access-tokens/new")!, aliases: ["gh"]),
        KeyService(id: "stripe", name: "Stripe", url: URL(string: "https://dashboard.stripe.com/apikeys")!),
        KeyService(id: "huggingface", name: "Hugging Face", url: URL(string: "https://huggingface.co/settings/tokens")!, aliases: ["hf", "hugging face"]),
        KeyService(id: "vercel", name: "Vercel", url: URL(string: "https://vercel.com/account/settings/tokens")!),
        KeyService(id: "replicate", name: "Replicate", url: URL(string: "https://replicate.com/account/api-tokens")!),
        KeyService(id: "openrouter", name: "OpenRouter", url: URL(string: "https://openrouter.ai/settings/keys")!),
        KeyService(id: "groq", name: "Groq", url: URL(string: "https://console.groq.com/keys")!),
    ]

    /// A registry entry by id, name or alias; otherwise the site itself ("example.com" or "example" → example.com).
    public static func resolve(_ input: String) -> KeyService? {
        let raw = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let q = raw.lowercased()
        guard !q.isEmpty else { return nil }
        if let hit = registry.first(where: { $0.id == q || $0.name.lowercased() == q || $0.aliases.contains(q) }) { return hit }
        let host = q.contains(".") ? q : q.replacingOccurrences(of: " ", with: "") + ".com"
        guard let url = URL(string: host.contains("://") ? host : "https://" + host), isSafeBrowserURL(url) else { return nil }
        let id = (url.host ?? q).replacingOccurrences(of: "www.", with: "")
        return KeyService(id: id, name: raw, url: url, known: false)
    }

    static func defaultKeyName(_ date: Date = Date()) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyyMMdd-HHmmss"
        return "agent-" + f.string(from: date)
    }
}

/// http(s) with a host.
func isSafeBrowserURL(_ url: URL) -> Bool {
    guard let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else { return false }
    return url.host != nil
}

// MARK: - Capture

/// Reads new key-like values in the private `agentKeychain` world and hands them straight to the
/// `Vault` through a message handler registered only in that world. Page scripts cannot see or
/// call it; the value never passes through a snapshot, redaction, a model or a log.
@MainActor
final class SecretCapture: NSObject, WKScriptMessageHandler {
    static let handlerName = "agentKeychainCapture"

    private weak var webView: WKWebView?
    private let vault: Vault
    private let account: String
    private let keyName: String
    private var scanId = 0
    private var received: [Int: Int] = [:]
    private var baselineScans: Set<Int> = []
    /// Hashes of values on the page before the key was created, so an old value is never taken for the new key.
    private var baseline: Set<String> = []
    private(set) var capturedHashes: Set<String> = []
    private(set) var saved: String?
    private(set) var saveError: String?

    init(webView: WKWebView, vault: Vault, account: String, keyName: String) {
        self.webView = webView
        self.vault = vault
        self.account = account
        self.keyName = keyName
    }

    private final class WeakHandler: NSObject, WKScriptMessageHandler {
        weak var target: SecretCapture?
        init(_ target: SecretCapture) { self.target = target }
        func userContentController(_ c: WKUserContentController, didReceive message: WKScriptMessage) {
            MainActor.assumeIsolated { target?.userContentController(c, didReceive: message) }
        }
    }

    func install() {
        guard let controller = webView?.configuration.userContentController else { return }
        controller.removeScriptMessageHandler(forName: Self.handlerName, contentWorld: PageDriver.world)
        controller.add(WeakHandler(self), contentWorld: PageDriver.world, name: Self.handlerName)
    }

    func uninstall() {
        webView?.configuration.userContentController
            .removeScriptMessageHandler(forName: Self.handlerName, contentWorld: PageDriver.world)
    }

    nonisolated static func hash(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// The save rule, kept pure for tests: a new (not baseline) secret-looking value that is not the key's name.
    nonisolated static func accepts(_ value: String, context: String, keyName: String, baseline: Set<String>) -> Bool {
        !baseline.contains(hash(value)) && value != keyName && !keyName.contains(value) &&
            SecretDetector.isSecret(value, context: context)
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.world == PageDriver.world, let body = message.body as? [String: Any],
              let value = body["value"] as? String, let scan = body["scan"] as? Int else { return }
        received[scan, default: 0] += 1
        let context = body["context"] as? String ?? ""
        let h = Self.hash(value)
        if baselineScans.contains(scan) { baseline.insert(h); return }
        guard saved == nil, Self.accepts(value, context: context, keyName: keyName, baseline: baseline) else { return }
        do {
            saved = try vault.store(value, account: account)
            capturedHashes.insert(h)
        } catch {
            saveError = error.localizedDescription
        }
    }

    struct ScanResult { var posted = 0; var loginWall = false }

    /// Posts every candidate token on the page to the handler, then waits until all arrived.
    /// The script returns only a count and a sign-in flag, never a value.
    @discardableResult
    func scan(baseline isBaseline: Bool = false) async -> ScanResult {
        guard let webView else { return ScanResult() }
        scanId += 1
        let id = scanId
        if isBaseline { baselineScans.insert(id) }
        let result = try? await webView.callAsyncJavaScript(Self.scanScript, arguments: ["scan": id, "name": keyName],
                                                           in: nil, contentWorld: PageDriver.world)
        let dict = result as? [String: Any] ?? [:]
        let posted = (dict["posted"] as? NSNumber)?.intValue ?? 0
        let deadline = Date().addingTimeInterval(1)
        while received[id, default: 0] < posted, Date() < deadline {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return ScanResult(posted: posted, loginWall: (dict["login"] as? NSNumber)?.boolValue ?? false)
    }

    /// Same rule as `SecretDetector.candidatePattern`, capped at 256 characters.
    static let candidateRegexJS = #"/(?<![A-Za-z0-9_\-\/=.?&#%@])[A-Za-z0-9_\-]{20,256}(?![A-Za-z0-9_\-\/])/g"#

    /// Text nodes (including `<code>`), and visible input/textarea values (password fields are
    /// skipped). Tokens inside URLs/paths are not candidates. Each value is posted once per document.
    /// The page's own Copy button writes to the clipboard from the page world, which this world
    /// cannot wrap without exposing the handler to the page, so the shown value is read instead.
    static let scanScript = #"""
    const handler = window.webkit?.messageHandlers?.agentKeychainCapture;
    const vis = e => !!e && (!e.checkVisibility || e.checkVisibility({checkOpacity:true, checkVisibilityCSS:true}));
    const pw = [...document.querySelectorAll('input[type=password]:not([readonly]):not([disabled])')].some(vis);
    const user = [...document.querySelectorAll('input[type=email],input[autocomplete~=username],input[name*=email i],input[name*=login i]')].some(vis);
    const loginPlace = /(log-?in|sign-?in|auth|sso)/i.test(location.pathname) || /^(accounts?|login|auth|sso|signin)\./i.test(location.hostname);
    // A password field with a username field, or on a sign-in URL. A lone password-type field
    // (some dashboards show a key that way) is not a sign-in wall.
    const login = (pw && (user || loginPlace)) || (loginPlace && user);
    if (!handler || !document.body) return {posted: 0, login};
    const seen = window.__agentKeychainSeen ||= new Set();
    const re = \#(candidateRegexJS);
    // Context = the label right next to the value, not the whole container, so an unlabeled
    // id below a "token" field is not mistaken for the token (see SecretDetector).
    const near = el => (el?.previousElementSibling?.textContent || '').slice(-80);
    const fieldContext = e => {
      const own = [e.getAttribute('aria-label'), e.getAttribute('placeholder'), e.getAttribute('title'),
        e.getAttribute('name'), e.id, ...[...(e.labels || [])].map(l => l.textContent)].filter(Boolean).join(' ');
      return own || near(e) || near(e.parentElement);
    };
    const out = [];
    const add = (text, contextFor) => {
      for (const m of text.matchAll(re)) {
        const v = m[0];
        if (seen.has(v) || v === name) continue;
        seen.add(v);
        out.push({value: v, context: contextFor(m.index).replace(/\s+/g, ' ').slice(-300), scan});
      }
    };
    for (const e of document.querySelectorAll('input,textarea')) {
      if (['password', 'hidden', 'file'].includes(e.type) || !vis(e) || !e.value) continue;
      add(e.value, () => fieldContext(e));
    }
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const p = n.parentElement, t = n.textContent;
      if (!p || t.length < 20 || p.closest('script,style,noscript,template') || !vis(p)) continue;
      add(t, i => {
        const before = t.slice(Math.max(0, i - 48), i);
        const label = p.getAttribute('aria-label') || '';
        return before.trim() || label ? label + ' ' + before : near(p) || near(p.parentElement);
      });
    }
    for (const x of out) handler.postMessage(x);
    return {posted: out.length, login};
    """#
}

// MARK: - Grab window

/// One grab: a small window on the service's key page, a capture scan every second, and the
/// page tools (snapshot/click/type) with captured and detected secrets masked.
@MainActor
final class GrabSession: NSObject, NSWindowDelegate {
    let service: KeyService
    let keyName: String
    let account: String
    private let window: NSWindow
    private let webView: WKWebView
    private let capture: SecretCapture
    private let driver: PageDriver
    /// nil until a page without a sign-in wall was seen; scans before this date only record what was already there.
    private var baselineUntil: Date?
    private(set) var loginWall = false
    private(set) var closed = false

    var saved: String? { capture.saved }
    var saveError: String? { capture.saveError }

    init(service: KeyService, keyName: String, vault: Vault) {
        self.service = service
        self.keyName = keyName
        account = "\(service.id)/\(keyName)"
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .default() // this binary's own persistent store, not Safari's or Brave's
        webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 1000, height: 760), configuration: config)
        window = NSWindow(contentRect: webView.frame, styleMask: [.titled, .closable, .resizable, .miniaturizable],
                          backing: .buffered, defer: false)
        capture = SecretCapture(webView: webView, vault: vault, account: account, keyName: keyName)
        driver = PageDriver(webView: webView)
        super.init()
        window.title = "agent-keychain — create a \(service.name) key named \(keyName)"
        window.contentView = webView
        window.isReleasedWhenClosed = false
        window.delegate = self
        capture.install()
    }

    func open() {
        NSApp.setActivationPolicy(.regular)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        webView.load(URLRequest(url: service.url))
        Task { await loop() }
    }

    func close() {
        guard !closed else { return }
        window.close()
    }

    func windowWillClose(_ notification: Notification) {
        closed = true
        capture.uninstall()
        clearPasteboardIfCaptured()
        webView.stopLoading()
    }

    private func loop() async {
        while !closed, saved == nil {
            if !webView.isLoading { await scanNow() }
            clearPasteboardIfCaptured()
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
        guard saved != nil, !closed else { return }
        window.title = "Saved \(saved!) to the Keychain. This window closes itself."
        clearPasteboardIfCaptured()
        try? await Task.sleep(nanoseconds: 1_200_000_000)
        close()
    }

    private func scanNow() async {
        let inBaseline = baselineUntil.map { Date() < $0 } ?? true
        let r = await capture.scan(baseline: inBaseline)
        loginWall = r.loginWall
        // Dashboards render in pieces; keep recording for 2 s after the first signed-in page.
        if baselineUntil == nil, !r.loginWall { baselineUntil = Date().addingTimeInterval(2) }
    }

    /// The page's own Copy button could put the key where an agent can `pbpaste` it.
    private func clearPasteboardIfCaptured() {
        let board = NSPasteboard.general
        guard let s = board.string(forType: .string), !capture.capturedHashes.isEmpty else { return }
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if capture.capturedHashes.contains(SecretCapture.hash(trimmed)) { board.clearContents() }
    }

    // MARK: Page tools

    func snapshot() async throws -> PageSnapshot {
        guard !closed else { throw AgentError.stalePage("The grab window is closed.") }
        var snap = try await driver.snapshot()
        await scanNow()
        let hashes = capture.capturedHashes
        guard !hashes.isEmpty else { return snap }
        let mask: (String) -> String = { text in
            var out = text
            for c in Set(SecretDetector.candidates(in: text)) where hashes.contains(SecretCapture.hash(c)) {
                out = out.replacingOccurrences(of: c, with: AgentRedaction.mask)
            }
            return out
        }
        snap.title = mask(snap.title)
        snap.text = mask(snap.text)
        snap.actions = snap.actions.map { a in
            var a = a
            a.label = mask(a.label)
            a.value = a.value.map(mask)
            a.currentValue = a.currentValue.map(mask)
            return a
        }
        return snap
    }

    func click(_ ref: String) async throws -> PageSnapshot {
        guard !closed else { throw AgentError.stalePage("The grab window is closed.") }
        try await driver.click(ref)
        return try await snapshot()
    }

    func type(_ ref: String, text: String) async throws -> PageSnapshot {
        guard !closed else { throw AgentError.stalePage("The grab window is closed.") }
        try await driver.type(ref, text: text)
        return try await snapshot()
    }

    func scroll(down: Bool) async throws -> PageSnapshot {
        guard !closed else { throw AgentError.stalePage("The grab window is closed.") }
        try await driver.scroll(down: down)
        return try await snapshot()
    }
}

/// What the MCP tools call. One grab window at a time.
public protocol Grabbing: AnyObject {
    func grab(service: String, name: String?, wait: TimeInterval) async throws -> JSONValue
    func snapshot() async throws -> String
    func click(_ ref: String) async throws -> String
    func type(_ ref: String, text: String) async throws -> String
    func scroll(down: Bool) async throws -> String
}

public final class GrabManager: Grabbing {
    let vault: Vault
    @MainActor private var session: GrabSession?

    public init(vault: Vault) { self.vault = vault }

    public func grab(service input: String, name: String?, wait: TimeInterval) async throws -> JSONValue {
        guard let service = KeyService.resolve(input) else { throw RunError.invalid("Unknown service or bad URL: \(input).") }
        let keyName = name?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty ?? KeyService.defaultKeyName()
        let s: GrabSession = await MainActor.run {
            // Calling again for the same service (and name, if given) resumes waiting in the open window.
            if let s = session, !s.closed, s.saved == nil, s.service.id == service.id, name == nil || s.keyName == keyName {
                return s
            }
            session?.close()
            let s = GrabSession(service: service, keyName: keyName, vault: vault)
            session = s
            s.open()
            return s
        }
        let deadline = Date().addingTimeInterval(wait)
        while true {
            let state = await MainActor.run { (s.saved, s.closed, s.loginWall, s.saveError, s.account) }
            if let saved = state.0 {
                return .object(["status": "saved", "saved": .string(saved),
                                "message": "Saved to the Keychain. Use it with run_with_secret; the value is never shown."])
            }
            if let error = state.3 { return .object(["status": "failed", "message": .string("Found a key but could not save it: \(error)")]) }
            if state.1 { return .object(["status": "closed", "message": "The window was closed before a new key appeared."]) }
            if Date() >= deadline {
                let msg = state.2
                    ? "Waiting for the user to sign in to \(service.name) in the agent-keychain window. Never type passwords. Call grab_key again to keep waiting."
                    : "The window is open on \(service.url.absoluteString). Create a key named \(keyName) there (the user, or you via page_snapshot/page_click/page_type), then call grab_key again to wait."
                return .object(["status": .string(state.2 ? "waiting_for_user_sign_in" : "waiting"),
                                "pending": .string(state.4), "message": .string(msg)])
            }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
    }

    @MainActor private func open() throws -> GrabSession {
        guard let s = session, !s.closed else { throw AgentError.stalePage("No grab window is open. Call grab_key first.") }
        return s
    }

    public func snapshot() async throws -> String { render(try await open().snapshot()) }
    public func click(_ ref: String) async throws -> String { render(try await open().click(ref)) }
    public func type(_ ref: String, text: String) async throws -> String { render(try await open().type(ref, text: text)) }
    public func scroll(down: Bool) async throws -> String { render(try await open().scroll(down: down)) }
}

/// Snapshot text for a model. Every field is already redacted by `PageSnapshot.decode` and masked by `GrabSession`.
func render(_ s: PageSnapshot, maxText: Int = 8000) -> String {
    var lines = ["URL: \(s.url)", "Title: \(s.title)", ""]
    lines.append(s.text.count > maxText ? String(s.text.prefix(maxText)) + "\n[text truncated]" : s.text)
    lines.append("")
    lines.append("Actions (use the ref with page_click / page_type):")
    for a in s.actions {
        var line = "\(a.id) [\(a.kind)\(a.role.map { " " + $0 } ?? "")] \(a.label)"
        if let v = a.currentValue, !v.isEmpty { line += " = \(v)" }
        lines.append(line)
    }
    if s.omittedActions > 0 { lines.append("(\(s.omittedActions) more actions omitted)") }
    return lines.joined(separator: "\n")
}

extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
