// swift-tools-version: 5.9
//
// Package manifest for the iOS SwiftUI client.
//
// The Info.plist used for runtime configuration previously lived at the target
// root and was processed as a SwiftPM resource. Starting with SwiftPM 5.9 this
// caused a build error because Info.plist cannot reside at the bundle's root.
// The file now sits under `Resources/Config/` and is excluded from resource
// processing. The app reads configuration keys from its main bundle directly.
import PackageDescription

let package = Package(
    name: "PrivateLine",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(name: "PrivateLine", targets: ["PrivateLine"]),
    ],
    targets: [
        // The main app target reads configuration directly from its bundle's
        // Info.plist. The file now lives under Resources/Config/ for Xcode but
        // should not be treated as a SwiftPM resource to avoid build errors.
        .target(name: "PrivateLine", path: "PrivateLine"),
        .testTarget(name: "PrivateLineTests", dependencies: ["PrivateLine"], path: "PrivateLineTests"),
    ]
)
