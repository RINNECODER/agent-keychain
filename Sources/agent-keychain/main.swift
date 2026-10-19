import AgentKeychainCore
import AppKit
import Foundation

let usage = """
agent-keychain: let AI agents grab and use API keys without seeing them.

  agent-keychain list                         saved key names
  agent-keychain grab <service> [name]        open the key page; the new key goes to the Keychain
  agent-keychain run -e VAR=<service/name> [-e …] [-C dir] [--timeout s] -- <command> [args…]
  agent-keychain delete <service/name>
  agent-keychain mcp                          MCP server on stdio
"""

func fail(_ message: String, code: Int32 = 2) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

/// Runs `work` while the main thread runs AppKit (needed for windows and the auth prompt), then exits.
func runApp(_ work: @escaping () async -> Int32) -> Never {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    Task { exit(await work()) }
    app.run()
    exit(0)
}

let vault = Vault()
var argv = Array(CommandLine.arguments.dropFirst())
guard let sub = argv.first else { fail(usage) }
argv.removeFirst()

switch sub {
case "list":
    let f = ISO8601DateFormatter()
    for item in vault.items() { print(item.name + (item.created.map { "\t" + f.string(from: $0) } ?? "")) }

case "grab":
    guard let service = argv.first else { fail(usage) }
    let name = argv.count > 1 ? argv[1...].joined(separator: " ") : nil
    runApp {
        let grabber = GrabManager(vault: vault)
        do {
            let r = try await grabber.grab(service: service, name: name, wait: 24 * 3600)
            print(r["saved"]?.stringValue.map { "saved \($0)" } ?? (r["message"]?.stringValue ?? "not saved"))
            return r["saved"] == nil ? 1 : 0
        } catch {
            fail(error.localizedDescription, code: 1)
        }
    }

case "run":
    var env: [String: String] = [:]
    var cwd: String?
    var timeout: TimeInterval = 120
    while let a = argv.first, a != "--" {
        argv.removeFirst()
        switch a {
        case "-e", "--env":
            guard let kv = argv.first, let eq = kv.firstIndex(of: "=") else { fail(usage) }
            env[String(kv[..<eq])] = String(kv[kv.index(after: eq)...])
            argv.removeFirst()
        case "-C", "--cwd":
            guard let d = argv.first else { fail(usage) }
            cwd = d; argv.removeFirst()
        case "--timeout":
            guard let t = argv.first.flatMap(TimeInterval.init) else { fail(usage) }
            timeout = t; argv.removeFirst()
        default: fail(usage)
        }
    }
    guard argv.first == "--", argv.count > 1 else { fail(usage) }
    let command = argv[1], args = Array(argv.dropFirst(2))
    runApp {
        do {
            let r = try await SecretRunner(vault: vault, approver: LocalAuthApprover())
                .run(RunRequest(command: command, args: args, env: env, cwd: cwd, timeout: timeout))
            FileHandle.standardOutput.write(Data(r.stdout.utf8))
            FileHandle.standardError.write(Data(r.stderr.utf8))
            if r.timedOut { FileHandle.standardError.write(Data("agent-keychain: timed out\n".utf8)) }
            return r.exitCode
        } catch {
            fail(error.localizedDescription, code: 1)
        }
    }

case "delete":
    guard let name = argv.first else { fail(usage) }
    runApp {
        do {
            try await MCPServer(vault: vault, approver: LocalAuthApprover(), grabber: GrabManager(vault: vault)).deleteKey(name)
            print("deleted \(name)")
            return 0
        } catch {
            fail(error.localizedDescription, code: 1)
        }
    }

case "mcp":
    let server = MCPServer(vault: vault, approver: LocalAuthApprover(), grabber: GrabManager(vault: vault))
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    server.serveStdio { exit(0) }
    app.run()

case "-h", "--help", "help":
    print(usage)

default:
    fail(usage)
}
