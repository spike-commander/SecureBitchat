// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SecureBitchat",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "SecureBitchat",
            targets: ["SecureBitchat"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", exact: "0.21.1")
    ],
    targets: [
        .target(
            name: "SecureBitchat",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "P256K", package: "swift-secp256k1")
            ],
            path: "Sources/SecureBitchat"
        ),
        .testTarget(
            name: "SecureBitchatTests",
            dependencies: ["SecureBitchat"],
            path: "Tests/SecureBitchatTests"
        )
    ]
)
