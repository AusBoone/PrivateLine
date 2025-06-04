// swift-tools-version: 5.9
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
        .target(name: "PrivateLine", path: "PrivateLine"),
        .testTarget(name: "PrivateLineTests", dependencies: ["PrivateLine"], path: "PrivateLineTests"),
    ]
)
