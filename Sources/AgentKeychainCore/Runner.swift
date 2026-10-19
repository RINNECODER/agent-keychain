import Foundation
import LocalAuthentication

// MARK: - Output scrubbing

enum Scrubber {
    /// Forms a value can take in output: raw, base64 (standard and URL-safe, at any byte offset so
    /// `Basic base64(user:key)` is caught) and percent-encoded. Longest first.
    static func forms(of value: String) -> [String] {
        let data = Data(value.utf8)
        var out: Set<String> = [value]
        for k in 0..<3 {
            // With k filler bytes in front, the first ceil(4k/3) characters and the trailing partial
            // group depend on neighbouring bytes; the middle is the same wherever the value sits.
            let enc = (Data(repeating: 0, count: k) + data).base64EncodedString()
            let start = (4 * k + 2) / 3
            let end = ((data.count + k) / 3) * 4
            guard end - start >= 16 else { continue }
            let mid = String(Array(enc)[start..<end])
            out.insert(mid)
            out.insert(mid.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_"))
        }
        for allowed in [CharacterSet.alphanumerics, .urlQueryAllowed, .urlPathAllowed] {
            if let e = value.addingPercentEncoding(withAllowedCharacters: allowed) { out.insert(e) }
        }
        return out.filter { !$0.isEmpty }.sorted { $0.count > $1.count }
    }

    /// Replaces every form of every secret with `[secret:<name>]`, then runs the detector.
    static func scrub(_ text: String, secrets: [String: String]) -> String {
        var out = text
        let pairs = secrets.flatMap { name, value in forms(of: value).map { ($0, name) } }
            .sorted { $0.0.count > $1.0.count }
        // Derived forms of a very short value would wreck the output; the raw value is always masked.
        for (form, name) in pairs where form.count >= 4 || form == secrets[name] {
            out = out.replacingOccurrences(of: form, with: "[secret:\(name)]")
        }
        return AgentRedaction.redact(out)
    }
}

// MARK: - Approval

public protocol Approver: AnyObject {
    /// Asks the human; true only when they approved.
    func approve(reason: String) async -> Bool
}

/// Touch ID, Apple Watch or the login password.
public final class LocalAuthApprover: Approver {
    public init() {}
    public func approve(reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }
}

/// "Allow this command + keys for N minutes", in memory only (dies with the process).
final class ApprovalCache {
    private var until: [String: Date] = [:]
    private let lock = NSLock()
    var now: () -> Date = Date.init

    func allowed(_ key: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return (until[key] ?? .distantPast) > now()
    }

    func remember(_ key: String, minutes: Int) {
        guard minutes > 0 else { return }
        lock.lock(); defer { lock.unlock() }
        until[key] = now().addingTimeInterval(TimeInterval(minutes * 60))
    }
}

// MARK: - Run with secret

public struct RunRequest {
    public var command: String
    public var args: [String] = []
    /// Environment variable → key name ("openai/default").
    public var env: [String: String] = [:]
    public var cwd: String?
    public var timeout: TimeInterval = 120
    /// 0 = ask every time.
    public var rememberMinutes = 0

    public init(command: String, args: [String] = [], env: [String: String] = [:], cwd: String? = nil,
                timeout: TimeInterval = 120, rememberMinutes: Int = 0) {
        self.command = command; self.args = args; self.env = env; self.cwd = cwd
        self.timeout = timeout; self.rememberMinutes = rememberMinutes
    }
}

public struct RunResult: Equatable {
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String
    public var truncated: Bool
    public var timedOut: Bool
}

public enum RunError: LocalizedError, Equatable {
    case invalid(String)
    case denied
    public var errorDescription: String? {
        switch self {
        case .invalid(let m): return m
        case .denied: return "The user did not approve this run."
        }
    }
}

public final class SecretRunner {
    public static let outputCap = 64 * 1024
    static let maxTimeout: TimeInterval = 900
    static let maxRememberMinutes = 60

    let vault: Vault
    let approver: Approver
    let cache = ApprovalCache()

    public init(vault: Vault, approver: Approver) {
        self.vault = vault
        self.approver = approver
    }

    static func reason(_ r: RunRequest) -> String {
        var cmd = ([r.command] + r.args).joined(separator: " ")
        if cmd.count > 160 { cmd = String(cmd.prefix(160)) + "…" }
        let keys = r.env.sorted { $0.key < $1.key }.map { "\($0.value) as $\($0.key)" }.joined(separator: ", ")
        let remember = r.rememberMinutes > 0 ? " (and allow it again for \(r.rememberMinutes) min)" : ""
        return "give \(keys) to: \(cmd)\(remember)"
    }

    static func cacheKey(_ r: RunRequest) -> String {
        let env = r.env.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
        return ([r.command] + r.args + ["\u{0}", r.cwd ?? ""] + env).joined(separator: "\u{1}")
    }

    /// Absolute path of `command`: as given when it contains "/", else the first match on PATH.
    static func resolve(_ command: String, path: String? = ProcessInfo.processInfo.environment["PATH"]) -> String? {
        if command.contains("/") { return FileManager.default.isExecutableFile(atPath: command) ? command : nil }
        for dir in (path ?? "/usr/bin:/bin").split(separator: ":") {
            let p = "\(dir)/\(command)"
            if FileManager.default.isExecutableFile(atPath: p) { return p }
        }
        return nil
    }

    public func run(_ request: RunRequest) async throws -> RunResult {
        var r = request
        r.rememberMinutes = min(max(r.rememberMinutes, 0), Self.maxRememberMinutes)
        guard !r.env.isEmpty else { throw RunError.invalid("env must map at least one variable to a key name.") }
        for name in r.env.keys where name.range(of: #"^[A-Za-z_][A-Za-z0-9_]*$"#, options: .regularExpression) == nil {
            throw RunError.invalid("Invalid environment variable name \(name).")
        }
        guard let exe = Self.resolve(r.command) else { throw RunError.invalid("Command not found: \(r.command).") }
        if let cwd = r.cwd {
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: cwd, isDirectory: &isDir), isDir.boolValue else {
                throw RunError.invalid("cwd is not a directory: \(cwd).")
            }
        }
        // Check names exist before prompting, so a typo never costs a Touch ID prompt.
        let known = Set(vault.items().map(\.name))
        for key in r.env.values where !known.contains(key) { throw Vault.VaultError.notFound(key) }

        let key = Self.cacheKey(r)
        if !cache.allowed(key) {
            guard await approver.approve(reason: Self.reason(r)) else { throw RunError.denied }
            cache.remember(key, minutes: r.rememberMinutes)
        }
        var secrets: [String: String] = [:]
        var env = ProcessInfo.processInfo.environment
        for (variable, name) in r.env {
            guard let value = vault.value(name) else { throw Vault.VaultError.notFound(name) }
            secrets[name] = value
            env[variable] = value
        }
        let timeout = min(max(r.timeout, 1), Self.maxTimeout)
        let raw = try Self.spawn(exe, args: r.args, env: env, cwd: r.cwd, timeout: timeout)
        let out = Self.finish(raw.stdout, secrets: secrets)
        let err = Self.finish(raw.stderr, secrets: secrets)
        return RunResult(exitCode: raw.code, stdout: out.text, stderr: err.text,
                         truncated: raw.truncated || out.truncated || err.truncated, timedOut: raw.timedOut)
    }

    /// Scrubs before truncating, so a cut never leaves half a secret unmasked.
    static func finish(_ data: Data, secrets: [String: String]) -> (text: String, truncated: Bool) {
        let text = scrubbed(data, secrets: secrets)
        guard text.utf8.count > outputCap else { return (text, false) }
        return (String(decoding: Data(text.utf8).prefix(outputCap), as: UTF8.self) + "\n[output truncated]", true)
    }

    static func scrubbed(_ data: Data, secrets: [String: String]) -> String {
        Scrubber.scrub(String(decoding: data, as: UTF8.self), secrets: secrets)
    }

    struct Spawned { var code: Int32; var stdout: Data; var stderr: Data; var truncated: Bool; var timedOut: Bool }

    /// Captures up to cap + 16 KB per stream (the slack keeps a secret at the cut scrubbable) and drains the rest.
    static func spawn(_ exe: String, args: [String], env: [String: String], cwd: String?,
                      timeout: TimeInterval) throws -> Spawned {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        p.environment = env
        if let cwd { p.currentDirectoryURL = URL(fileURLWithPath: cwd) }
        p.standardInput = FileHandle.nullDevice
        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = errPipe

        let limit = outputCap + 16 * 1024
        let lock = NSLock()
        var bufs = [Data(), Data()]
        var over = false
        let streams = DispatchGroup()
        for (i, pipe) in [outPipe, errPipe].enumerated() {
            streams.enter()
            pipe.fileHandleForReading.readabilityHandler = { h in
                let chunk = h.availableData
                lock.lock(); defer { lock.unlock() }
                if chunk.isEmpty {
                    h.readabilityHandler = nil
                    streams.leave()
                    return
                }
                let room = limit - bufs[i].count
                if chunk.count > room { over = true }
                if room > 0 { bufs[i].append(chunk.prefix(room)) }
            }
        }
        let exited = DispatchSemaphore(value: 0)
        p.terminationHandler = { _ in exited.signal() }
        try p.run()
        var timedOut = false
        if exited.wait(timeout: .now() + timeout) == .timedOut {
            timedOut = true
            p.terminate()
            if exited.wait(timeout: .now() + 2) == .timedOut {
                kill(p.processIdentifier, SIGKILL)
                exited.wait()
            }
        }
        // A background grandchild can hold the pipes open; stop reading after a short grace.
        if streams.wait(timeout: .now() + 2) == .timedOut {
            outPipe.fileHandleForReading.readabilityHandler = nil
            errPipe.fileHandleForReading.readabilityHandler = nil
        }
        lock.lock(); defer { lock.unlock() }
        return Spawned(code: p.terminationStatus, stdout: bufs[0], stderr: bufs[1], truncated: over, timedOut: timedOut)
    }
}
