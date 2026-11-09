// swift-tools-version: 6.0
// Secure App for macOS, as a Swift package: the command-line build and the unit
// tests (scripts/build.sh, scripts/test.sh). The Xcode project (project.yml,
// SecureApp.xcodeproj) builds the same sources and is what makes the signed app
// with its provisioning profile and App Attest entitlement.
import PackageDescription

let swift5: [SwiftSetting] = [.swiftLanguageMode(.v5)]

let package = Package(
    name: "SecureApp",
    platforms: [.macOS("27.0")],
    products: [
        .library(name: "SecureAppKit", targets: ["SecureAppKit"]),
        .executable(name: "SecureApp", targets: ["SecureApp"]),
    ],
    targets: [
        .target(name: "SecureAppKit", path: "SecureAppKit", swiftSettings: swift5),
        .executableTarget(
            name: "SecureApp",
            dependencies: ["SecureAppKit"],
            path: "SecureApp",
            exclude: ["Info.plist", "SecureApp.entitlements", "SecureApp.Debug.entitlements", "Resources"],
            swiftSettings: swift5
        ),
        .testTarget(name: "SecureAppKitTests", dependencies: ["SecureAppKit"], path: "SecureAppKitTests", swiftSettings: swift5),
    ]
)
