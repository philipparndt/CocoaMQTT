// swift-tools-version:5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CocoaMQTT",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13)
    ],
    products: [
        .library(name: "CocoaMQTT", targets: ["CocoaMQTT"]),
        .library(name: "CocoaMQTTWebSocket", targets: ["CocoaMQTTWebSocket"])
    ],
    dependencies: [
        // SwiftLint command plugin used by CI/local lint commands only.
        // We do not attach it as a build tool plugin to avoid affecting build outputs.
        .package(url: "https://github.com/SimplyDanny/SwiftLintPlugins", from: "0.63.2"),
    ],
    targets: [
        .target(
            name: "CocoaMQTT",
            dependencies: [],
            path: "Source",
            exclude: ["CocoaMQTTWebSocket.swift"],
            swiftSettings: [.define("IS_SWIFT_PACKAGE")]
        ),
        .target(
            name: "CocoaMQTTWebSocket",
            dependencies: ["CocoaMQTT"],
            path: "Source",
            sources: ["CocoaMQTTWebSocket.swift"],
            swiftSettings: [.define("IS_SWIFT_PACKAGE")]
        ),
        .testTarget(
            name: "CocoaMQTTTests",
            dependencies: ["CocoaMQTT", "CocoaMQTTWebSocket"],
            path: "CocoaMQTTTests",
            swiftSettings: [.define("IS_SWIFT_PACKAGE")]
        )
    ]
)
