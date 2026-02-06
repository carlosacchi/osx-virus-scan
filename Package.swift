// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "scan",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    ],
    targets: [
        .executableTarget(
            name: "scan",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            linkerSettings: [
                .linkedFramework("Security"),
            ]
        ),
        .testTarget(
            name: "scanTests",
            dependencies: ["scan"]
        ),
    ]
)
