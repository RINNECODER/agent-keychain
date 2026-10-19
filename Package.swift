// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "agent-keychain",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "AgentKeychainCore"),
        .executableTarget(name: "agent-keychain", dependencies: ["AgentKeychainCore"]),
        .testTarget(name: "AgentKeychainTests", dependencies: ["AgentKeychainCore"]),
    ]
)
