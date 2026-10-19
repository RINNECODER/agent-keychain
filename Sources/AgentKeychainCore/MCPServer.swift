import Foundation

/// MCP over stdio: newline-delimited JSON-RPC 2.0. Every tool result carries names and metadata
/// only; key values never enter a response.
public final class MCPServer {
    public static let version = "0.1.0"
    let vault: Vault
    let runner: SecretRunner
    let grabber: Grabbing
    let approver: Approver

    public init(vault: Vault, approver: Approver, grabber: Grabbing) {
        self.vault = vault
        self.approver = approver
        self.runner = SecretRunner(vault: vault, approver: approver)
        self.grabber = grabber
    }

    // MARK: Transport

    /// Reads requests from stdin until EOF, handling each concurrently; writes are serialized.
    public func serveStdio(onEOF: @escaping () -> Void) {
        let out = FileHandle.standardOutput
        let lock = NSLock()
        let inFlight = DispatchGroup()
        let thread = Thread {
            while let line = readLine(strippingNewline: true) {
                guard !line.trimmingCharacters(in: .whitespaces).isEmpty else { continue }
                inFlight.enter()
                Task {
                    defer { inFlight.leave() }
                    guard let response = await self.handle(line: line) else { return }
                    lock.withLock { out.write(Data((response + "\n").utf8)) }
                }
            }
            inFlight.wait() // answer what was asked before the client closed stdin
            onEOF()
        }
        thread.start()
    }

    /// One JSON-RPC message in, at most one out (notifications get none).
    public func handle(line: String) async -> String? {
        guard let msg = try? JSONDecoder().decode(JSONValue.self, from: Data(line.utf8)), let obj = msg.objectValue else {
            return Self.error(id: .null, code: -32700, "Parse error").jsonString()
        }
        let id = obj["id"]
        guard let method = obj["method"]?.stringValue else {
            return id == nil ? nil : Self.error(id: id!, code: -32600, "Invalid request").jsonString()
        }
        guard let id else { return nil } // notifications/initialized and friends
        let params = obj["params"]?.objectValue ?? [:]
        switch method {
        case "initialize":
            let requested = params["protocolVersion"]?.stringValue ?? "2025-06-18"
            return Self.result(id: id, [
                "protocolVersion": .string(requested),
                "capabilities": ["tools": .object([:])],
                "serverInfo": ["name": "agent-keychain", "version": .string(Self.version)],
                "instructions": .string(Self.instructions),
            ]).jsonString()
        case "ping":
            return Self.result(id: id, [:]).jsonString()
        case "tools/list":
            return Self.result(id: id, ["tools": .array(Self.tools)]).jsonString()
        case "tools/call":
            guard let name = params["name"]?.stringValue else {
                return Self.error(id: id, code: -32602, "Missing tool name").jsonString()
            }
            guard Self.tools.contains(where: { $0["name"]?.stringValue == name }) else {
                return Self.error(id: id, code: -32602, "Unknown tool: \(name)").jsonString()
            }
            let args = params["arguments"]?.objectValue ?? [:]
            do {
                let text = try await call(name, args)
                return Self.result(id: id, ["content": [["type": "text", "text": .string(text)]], "isError": .bool(false)]).jsonString()
            } catch {
                // Errors are written by this package and never contain values; redact anyway.
                let text = AgentRedaction.redact(error.localizedDescription)
                return Self.result(id: id, ["content": [["type": "text", "text": .string(text)]], "isError": .bool(true)]).jsonString()
            }
        default:
            return Self.error(id: id, code: -32601, "Method not found: \(method)").jsonString()
        }
    }

    static func result(id: JSONValue, _ result: [String: JSONValue]) -> JSONValue {
        ["jsonrpc": "2.0", "id": id, "result": .object(result)]
    }

    static func error(id: JSONValue, code: Int, _ message: String) -> JSONValue {
        ["jsonrpc": "2.0", "id": id, "error": ["code": .number(Double(code)), "message": .string(message)]]
    }

    // MARK: Tools

    func call(_ name: String, _ a: [String: JSONValue]) async throws -> String {
        func str(_ k: String) throws -> String {
            guard let v = a[k]?.stringValue, !v.isEmpty else { throw RunError.invalid("Missing argument \(k).") }
            return v
        }
        switch name {
        case "list_keys":
            let f = ISO8601DateFormatter()
            let keys: [JSONValue] = vault.items().map { item in
                var o: [String: JSONValue] = ["name": .string(item.name)]
                if let c = item.created { o["created"] = .string(f.string(from: c)) }
                return .object(o)
            }
            return JSONValue.object(["keys": .array(keys)]).jsonString()
        case "grab_key":
            let wait = min(max(a["wait_seconds"]?.numberValue ?? 120, 0), 600)
            return try await grabber.grab(service: try str("service"), name: a["name"]?.stringValue, wait: wait).jsonString()
        case "page_snapshot":
            return try await grabber.snapshot()
        case "page_click":
            return try await grabber.click(try str("ref"))
        case "page_type":
            guard let text = a["text"]?.stringValue else { throw RunError.invalid("Missing argument text.") }
            return try await grabber.type(try str("ref"), text: text)
        case "page_scroll":
            return try await grabber.scroll(down: a["direction"]?.stringValue != "up")
        case "run_with_secret":
            var env: [String: String] = [:]
            for (k, v) in a["env"]?.objectValue ?? [:] {
                guard let ref = v.stringValue else { throw RunError.invalid("env values must be key names.") }
                env[k] = ref
            }
            let args = try (a["args"].map { v -> [String] in
                guard case .array(let xs) = v else { throw RunError.invalid("args must be an array of strings.") }
                return try xs.map { guard let s = $0.stringValue else { throw RunError.invalid("args must be strings.") }; return s }
            }) ?? []
            let r = try await runner.run(RunRequest(
                command: try str("command"), args: args, env: env, cwd: a["cwd"]?.stringValue,
                timeout: a["timeout_seconds"]?.numberValue ?? 120,
                rememberMinutes: Int(a["remember_minutes"]?.numberValue ?? 10)))
            return JSONValue.object([
                "exit_code": .number(Double(r.exitCode)), "stdout": .string(r.stdout), "stderr": .string(r.stderr),
                "truncated": .bool(r.truncated), "timed_out": .bool(r.timedOut),
            ]).jsonString()
        case "delete_key":
            let key = try str("name")
            try await deleteKey(key)
            return JSONValue.object(["deleted": .string(key)]).jsonString()
        default:
            throw RunError.invalid("Unknown tool \(name).")
        }
    }

    /// Asks the user first.
    public func deleteKey(_ key: String) async throws {
        guard vault.items().contains(where: { $0.name == key }) else { throw Vault.VaultError.notFound(key) }
        guard await approver.approve(reason: "delete the API key \(key) from the Keychain") else { throw RunError.denied }
        try vault.delete(key)
    }

    static let instructions = """
    API keys live in the macOS Keychain and are never shown to you. Never ask the user to paste a key, \
    and never print, echo or log environment variables that hold one. To get a key, call grab_key. \
    To use one, call run_with_secret with env mapping a variable to the key name; the user approves each run.
    """

    static func tool(_ name: String, _ description: String, _ properties: [String: JSONValue] = [:],
                     required: [String] = []) -> JSONValue {
        ["name": .string(name), "description": .string(description),
         "inputSchema": ["type": "object", "properties": .object(properties), "required": .array(required.map { .string($0) })]]
    }

    static let tools: [JSONValue] = [
        tool("list_keys", "Names (\"<service>/<key name>\") and creation dates of saved API keys. Never values."),
        tool("grab_key", """
        Opens a small window on the service's API-key page (known: openai, anthropic, google-ai-studio, github, stripe, \
        huggingface, vercel, replicate, openrouter, groq; anything else opens that site). When a new key appears on the page \
        it is saved straight to the Keychain and the window closes. Returns {status, saved: "<service>/<name>"} or a waiting \
        status: call again to keep waiting. The user signs in; never type passwords. Drive the page with page_snapshot / \
        page_click / page_type if the user wants you to create the key.
        """, [
            "service": ["type": "string", "description": "Service id, name or site, e.g. \"openai\" or \"example.com\"."],
            "name": ["type": "string", "description": "Name for the new key (default: agent-<timestamp>)."],
            "wait_seconds": ["type": "number", "description": "How long to wait for the key (0-600, default 120)."],
        ], required: ["service"]),
        tool("page_snapshot", "Text and actionable elements of the grab window's page, with secrets masked."),
        tool("page_click", "Clicks an element by ref from the latest page_snapshot; returns the new snapshot.",
             ["ref": ["type": "string"]], required: ["ref"]),
        tool("page_type", "Types text into a field by ref from the latest page_snapshot (e.g. the key's name). Never passwords.",
             ["ref": ["type": "string"], "text": ["type": "string"]], required: ["ref", "text"]),
        tool("page_scroll", "Scrolls the grab window's page; returns the new snapshot.",
             ["direction": ["type": "string", "enum": ["down", "up"]]]),
        tool("run_with_secret", """
        Runs a command (no shell unless you pass /bin/sh -c) with saved keys injected as environment variables, after the \
        user approves with Touch ID or their password. Returns exit code and output with every injected value (and its \
        base64/URL-encoded forms) replaced by [secret:<name>]. Do not try to print the variables.
        """, [
            "command": ["type": "string", "description": "Executable name or path."],
            "args": ["type": "array", "items": ["type": "string"]],
            "env": ["type": "object", "additionalProperties": ["type": "string"],
                    "description": "Variable → key name, e.g. {\"OPENAI_API_KEY\": \"openai/default\"}."],
            "cwd": ["type": "string"],
            "timeout_seconds": ["type": "number", "description": "1-900, default 120."],
            "remember_minutes": ["type": "number", "description": "Skip the prompt for this exact command + keys for N minutes (0-60, default 10). Shown in the prompt."],
        ], required: ["command", "env"]),
        tool("delete_key", "Deletes a saved key after the user approves.", ["name": ["type": "string"]], required: ["name"]),
    ]
}

extension JSONValue: ExpressibleByDictionaryLiteral, ExpressibleByArrayLiteral {
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { $1 }))
    }
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
}
