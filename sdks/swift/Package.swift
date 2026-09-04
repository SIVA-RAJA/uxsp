// swift-tools-version: 5.9
// UXSP Swift iOS/macOS Client SDK - Version 1.2.0
// Author: SIVA RAJA S

import PackageDescription

let package = Package(
    name: "UXSPSdk",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "UXSPSdk",
            targets: ["UXSPSdk"]),
    ],
    targets: [
        .target(
            name: "UXSPSdk",
            dependencies: []),
    ]
)
