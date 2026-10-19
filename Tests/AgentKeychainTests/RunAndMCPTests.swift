@testable import AgentKeychainCore
import XCTest

final class VaultTests: XCTestCase {
    func testStoreNeverOverwritesAndListsNamesOnly() throws {
        let store = MemoryStore()
        let vault = Vault(store: store)
        let names = try ["first", "second", "third"].map { try vault.store($0 + "-value", account: "openai/ci") }
        XCTAssertEqual(names, ["openai/ci", "openai/ci-2", "openai/ci-3"])
        XCTAssertEqual(vault.value("openai/ci"), "first-value")
        XCTAssertEqual(vault.value("openai/ci-2"), "second-value")
        XCTAssertEqual(vault.items().map(\.name), ["openai/ci-3", "openai/ci-2", "openai/ci"]) // newest first
        try vault.delete("openai/ci-2")
        XCTAssertThrowsError(try vault.delete("openai/ci-2"))
        XCTAssertEqual(vault.items().count, 2)
    }
}

final class ScrubberTests: XCTestCase {
    func testMasksRawBase64AndURLEncodedForms() {
        let value = "k3y+" + randomToken(36) + "/=&x"
        let name = "openai/ci"
        let b64 = Data(value.utf8).base64EncodedString()
        let urlSafe = b64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        let basic = Data("user:\(value)".utf8).base64EncodedString()  // value at a non-zero byte offset
        let pct = value.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let text = "raw=\(value)\nb64=\(b64)\nurlsafe=\(urlSafe)\nAuthorization: Basic \(basic)\nq=\(pct)\n"
        let out = Scrubber.scrub(text, secrets: [name: value])
        for leak in [value, b64, urlSafe, basic, pct, String(value.dropFirst(4).prefix(30))] {
            XCTAssertFalse(out.contains(leak), "leaked \(leak): \(out)")
        }
        XCTAssertTrue(out.hasPrefix("raw=[secret:openai/ci]\n"), out)
        XCTAssertTrue(out.contains("Basic "), out)
        // Unrelated output survives.
        XCTAssertEqual(Scrubber.scrub("HTTP 200 OK, 12 models", secrets: [name: value]), "HTTP 200 OK, 12 models")
    }

    func testShortValueStillMaskedRaw() {
        XCTAssertEqual(Scrubber.scrub("pin=ab!", secrets: ["x/y": "ab"]), "pin=[secret:x/y]!")
    }
}

final class RunnerTests: XCTestCase {
    var store: MemoryStore!
    var vault: Vault!
    var approver: FakeApprover!
    var runner: SecretRunner!
    let value = "sk-proj-" + randomToken(40)

    override func setUpWithError() throws {
        store = MemoryStore()
        vault = Vault(store: store)
        try vault.store(value, account: "openai/ci")
        approver = FakeApprover()
        runner = SecretRunner(vault: vault, approver: approver)
    }

    func testInjectsEnvAndScrubsOutput() async throws {
        let r = try await runner.run(RunRequest(command: "/bin/sh",
            args: ["-c", #"printf '%s\n' "$OPENAI_API_KEY"; printf '%s' "$OPENAI_API_KEY" | base64; echo "$OPENAI_API_KEY" >&2; exit 3"#],
            env: ["OPENAI_API_KEY": "openai/ci"]))
        XCTAssertEqual(r.exitCode, 3)
        XCTAssertEqual(r.stdout.split(separator: "\n").map(String.init), ["[secret:openai/ci]", "[secret:openai/ci]"])
        XCTAssertEqual(r.stderr, "[secret:openai/ci]\n")
        XCTAssertEqual(approver.reasons.count, 1)
        XCTAssertTrue(approver.reasons[0].contains("openai/ci as $OPENAI_API_KEY"), approver.reasons[0])
        XCTAssertTrue(approver.reasons[0].contains("/bin/sh -c"), approver.reasons[0])
        XCTAssertFalse(approver.reasons[0].contains(value))
    }

    func testDeniedApprovalRunsNothing() async throws {
        approver.answer = false
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent("ak-\(UUID().uuidString)").path
        do {
            _ = try await runner.run(RunRequest(command: "/usr/bin/touch", args: [marker], env: ["K": "openai/ci"]))
            XCTFail("ran without approval")
        } catch {
            XCTAssertEqual(error as? RunError, .denied)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker))
    }

    func testUnknownKeyAndBadInputFailBeforePrompting() async {
        for req in [RunRequest(command: "/usr/bin/true", env: ["K": "nope/x"]),
                    RunRequest(command: "/usr/bin/true", env: ["BAD-NAME": "openai/ci"]),
                    RunRequest(command: "no-such-binary-ak", env: ["K": "openai/ci"]),
                    RunRequest(command: "/usr/bin/true")] {
            do { _ = try await runner.run(req); XCTFail("accepted \(req)") } catch {}
        }
        XCTAssertTrue(approver.reasons.isEmpty)
    }

    func testRememberCacheSkipsPromptForSameCommandOnly() async throws {
        let req = RunRequest(command: "true", env: ["K": "openai/ci"], rememberMinutes: 10)
        _ = try await runner.run(req)
        _ = try await runner.run(req)
        XCTAssertEqual(approver.reasons.count, 1)
        XCTAssertTrue(approver.reasons[0].contains("for 10 min"))
        _ = try await runner.run(RunRequest(command: "true", args: ["x"], env: ["K": "openai/ci"], rememberMinutes: 10))
        XCTAssertEqual(approver.reasons.count, 2)
        runner.cache.now = { Date().addingTimeInterval(11 * 60) }
        _ = try await runner.run(req)
        XCTAssertEqual(approver.reasons.count, 3)
    }

    func testOutputCapAndTimeout() async throws {
        let big = try await runner.run(RunRequest(command: "/bin/sh", args: ["-c", "head -c 200000 /dev/zero | tr '\\0' a"],
                                                  env: ["K": "openai/ci"]))
        XCTAssertTrue(big.truncated)
        XCTAssertLessThan(big.stdout.utf8.count, SecretRunner.outputCap + 100)
        let slow = try await runner.run(RunRequest(command: "/bin/sleep", args: ["30"], env: ["K": "openai/ci"], timeout: 1))
        XCTAssertTrue(slow.timedOut)
    }
}

final class MCPTests: XCTestCase {
    var server: MCPServer!
    var approver: FakeApprover!
    var grabber: FakeGrabber!
    let value = "sk-proj-" + randomToken(40)

    override func setUpWithError() throws {
        let vault = Vault(store: MemoryStore())
        try vault.store(value, account: "openai/ci")
        approver = FakeApprover()
        grabber = FakeGrabber()
        server = MCPServer(vault: vault, approver: approver, grabber: grabber)
    }

    func send(_ method: String, _ params: JSONValue = [:], id: JSONValue = .number(1)) async throws -> JSONValue {
        let line = JSONValue.object(["jsonrpc": "2.0", "id": id, "method": .string(method), "params": params]).jsonString()
        let raw = await server.handle(line: line)
        let out = try XCTUnwrap(raw)
        XCTAssertFalse(out.contains(value), "value leaked: \(out)")
        return try JSONDecoder().decode(JSONValue.self, from: Data(out.utf8))
    }

    func call(_ tool: String, _ args: JSONValue = [:]) async throws -> (text: String, isError: Bool) {
        let r = try await send("tools/call", ["name": .string(tool), "arguments": args])
        let result = try XCTUnwrap(r["result"])
        guard case .array(let content)? = result["content"], let text = content.first?["text"]?.stringValue,
              case .bool(let isError)? = result["isError"] else { XCTFail("bad shape \(r)"); return ("", true) }
        return (text, isError)
    }

    func testInitializeAndToolsList() async throws {
        let r = try await send("initialize", ["protocolVersion": "2025-06-18", "capabilities": [:],
                                              "clientInfo": ["name": "test", "version": "1"]])
        XCTAssertEqual(r["result"]?["protocolVersion"], "2025-06-18")
        XCTAssertEqual(r["result"]?["serverInfo"]?["name"], "agent-keychain")
        XCTAssertNotNil(r["result"]?["capabilities"]?["tools"])
        let note = await server.handle(line: #"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        XCTAssertNil(note)

        let list = try await send("tools/list", id: "abc")
        XCTAssertEqual(list["id"], "abc")
        guard case .array(let tools)? = list["result"]?["tools"] else { return XCTFail("no tools") }
        XCTAssertEqual(Set(tools.compactMap { $0["name"]?.stringValue }),
                       ["list_keys", "grab_key", "page_snapshot", "page_click", "page_type", "page_scroll", "run_with_secret", "delete_key"])
        for t in tools { XCTAssertEqual(t["inputSchema"]?["type"], "object") }
    }

    func testErrors() async throws {
        let unknownTool = try await send("tools/call", ["name": "get_key_value", "arguments": [:]])
        XCTAssertEqual(unknownTool["error"]?["code"], .number(-32602))
        let unknownMethod = try await send("resources/list")
        XCTAssertEqual(unknownMethod["error"]?["code"], .number(-32601))
        let parseRaw = await server.handle(line: "{not json")
        let parse = try XCTUnwrap(parseRaw)
        XCTAssertTrue(parse.contains("-32700"), parse)
        let missing = try await call("grab_key")
        XCTAssertTrue(missing.isError)
        let noWindow = try await call("page_snapshot")
        XCTAssertTrue(noWindow.isError)
        XCTAssertTrue(noWindow.text.contains("grab_key"))
    }

    func testListGrabRunDeleteShapes() async throws {
        let list = try await call("list_keys")
        XCTAssertFalse(list.isError)
        XCTAssertTrue(list.text.contains(#""name":"openai/ci""#), list.text)
        XCTAssertTrue(list.text.contains(#""created":"#), list.text)

        let grab = try await call("grab_key", ["service": "openai", "name": "ci2", "wait_seconds": .number(5)])
        XCTAssertEqual(grab.text, #"{"saved":"openai/ci2","status":"saved"}"#)
        XCTAssertEqual(grabber.grabs.first?.2, 5)

        let run = try await call("run_with_secret", ["command": "/usr/bin/printenv", "args": ["OPENAI_API_KEY"],
                                                     "env": ["OPENAI_API_KEY": "openai/ci"]])
        XCTAssertFalse(run.isError, run.text)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: Data(run.text.utf8))
        XCTAssertEqual(decoded["exit_code"], .number(0))
        XCTAssertEqual(decoded["stdout"], "[secret:openai/ci]\n")
        XCTAssertTrue(approver.reasons.last?.contains("allow it again for 10 min") ?? false)

        approver.answer = false
        let denied = try await call("delete_key", ["name": "openai/ci"])
        XCTAssertTrue(denied.isError)
        approver.answer = true
        let deleted = try await call("delete_key", ["name": "openai/ci"])
        XCTAssertEqual(deleted.text, #"{"deleted":"openai/ci"}"#)
        let empty = try await call("list_keys")
        XCTAssertEqual(empty.text, #"{"keys":[]}"#)
    }
}
