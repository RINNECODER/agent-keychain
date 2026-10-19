// Ported from browser-use/jev-ultrafast (MIT License, Copyright (c) 2026 Browser Use):
// Browser.observe / fresh / act and browser_operation() in jev_ultrafast/browser.py.

import Foundation
import WebKit

/// Snapshots and acts on a WKWebView through a private `agentKeychain` content world.
/// The tool methods (`snapshot`, `click`, `type`, `select`, `scroll`, `read`) are usable on
/// their own, e.g. over MCP; they act on ids from the most recent snapshot.
@MainActor
final class PageDriver {
    static let world = WKContentWorld.world(name: "agentKeychain")

    /// Weak so a cached driver never keeps a closed tab's page alive.
    private(set) weak var webView: WKWebView?
    private(set) var lastSnapshot: PageSnapshot?

    init(webView: WKWebView) {
        self.webView = webView
    }

    // MARK: Tools

    func read() async throws -> String {
        try await snapshot().text
    }

    @discardableResult
    func click(_ id: String) async throws -> PageSnapshot { try await tool(id, kinds: ["click"], text: nil) }

    @discardableResult
    func type(_ id: String, text: String) async throws -> PageSnapshot { try await tool(id, kinds: ["fill"], text: text) }

    @discardableResult
    func select(_ id: String) async throws -> PageSnapshot { try await tool(id, kinds: ["select"], text: nil) }

    @discardableResult
    func scroll(down: Bool) async throws -> PageSnapshot {
        let snap = try await snapshot()
        guard let action = snap.action(id: down ? "scroll_down" : "scroll_up") else { return snap }
        try await perform(action, text: nil)
        await settle(after: action)
        return try await snapshot()
    }

    private func tool(_ id: String, kinds: Set<String>, text: String?) async throws -> PageSnapshot {
        guard let snap = lastSnapshot, let action = snap.action(id: id), kinds.contains(action.kind) else {
            throw AgentError.stalePage("No \(kinds.sorted().joined(separator: "/")) action \(id) in the last snapshot. Take a snapshot first.")
        }
        guard await isFresh(snap, for: action) else {
            throw AgentError.stalePage("Page changed since the snapshot. Take a snapshot again.")
        }
        try await perform(action, text: text)
        await settle(after: action)
        return try await snapshot()
    }

    // MARK

    func snapshot() async throws -> PageSnapshot {
        await waitForLoad()
        for attempt in 0..<25 {
            if let json = try? await run(AgentPageScript.snapshotBody) as? String, !json.isEmpty {
                let snap = try PageSnapshot.decode(json)
                lastSnapshot = snap
                return snap
            }
            if attempt < 24 { try await Task.sleep(nanoseconds: 40_000_000) }
        }
        throw AgentError.stalePage("Page did not settle.")
    }

    func isFresh(_ snapshot: PageSnapshot, for action: PageAction?) async -> Bool {
        if let action, ["click", "select"].contains(action.kind) {
            guard let node = action.node, let expected = snapshot.nodeKeys[String(node)] else { return false }
            let current = try? await run(AgentPageScript.nodeKeyBody, ["node": node]) as? String
            return current == expected
        }
        let current = try? await run(AgentPageScript.markerBody) as? String
        return current == snapshot.marker
    }

    func perform(_ action: PageAction, text: String?) async throws {
        if action.kind == "wait" {
            try await Task.sleep(nanoseconds: 100_000_000)
            return
        }
        if action.kind == "fill", text == nil {
            throw AgentError.noText("TYPE_TEXT needs a value; nothing typed.")
        }
        let result: String?
        do {
            result = try await run(AgentPageScript.actBody,
                                   ["action": action.scriptArgument, "text": text ?? NSNull()]) as? String
        } catch {
            if action.kind == "select" {
                throw AgentError.unconfirmed("Dropdown execution was interrupted; inspect before retrying.")
            }
            throw AgentError.stalePage("Document changed during input. Observe again.")
        }
        switch result {
        case "ok": return
        case "unconfirmed": throw AgentError.unconfirmed("Dropdown execution was not confirmed; inspect before retrying.")
        default: throw AgentError.stalePage("Target changed or is covered. Observe again.")
        }
    }

    func settle(after action: PageAction) async {
        guard action.kind != "wait" else { return }
        // Read-only; a navigation that tears down the document just ends the wait.
        _ = try? await run(AgentPageScript.settleBody, ["action": action.scriptArgument], timeout: 0.5)
        await waitForLoad()
    }

    // MARK: Plumbing

    /// Waits (bounded) for an in-flight navigation to finish.
    private func waitForLoad(timeout: TimeInterval = 10) async {
        let deadline = Date().addingTimeInterval(timeout)
        while webView?.isLoading == true, Date() < deadline, !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 30_000_000)
        }
    }

    private enum RunError: Error { case timeout }

    /// Runs `library + body` in the agent world, with a timeout so a page that never
    /// resolves (or navigates away mid-call) cannot hang the loop.
    private func run(_ body: String, _ arguments: [String: Any] = [:], timeout: TimeInterval = 5) async throws -> Any? {
        guard let webView else { throw AgentError.stalePage("The tab was closed.") }
        let source = AgentPageScript.library + "\n" + body
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Any?, Error>) in
            var resumed = false
            let resume: (Result<Any?, Error>) -> Void = { result in
                guard !resumed else { return }
                resumed = true
                cont.resume(with: result)
            }
            webView.callAsyncJavaScript(source, arguments: arguments, in: nil, in: Self.world) { result in
                resume(result.map { Optional($0) })
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { resume(.failure(RunError.timeout)) }
        }
    }
}
