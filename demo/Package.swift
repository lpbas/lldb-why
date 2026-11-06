// swift-tools-version:6.0
// A command-line app with one crash per `why` rule. See demo/README.md.
import PackageDescription

let package = Package(
    name: "WhyDemo",
    platforms: [.macOS(.v13)],
    targets: [
        // C code standing in for an old Objective-C / C SDK that the Swift
        // compiler can't check for concurrency or nullability mistakes.
        .target(name: "LegacyAPI"),
        .executableTarget(name: "why-demo", dependencies: ["LegacyAPI"]),
    ]
)
