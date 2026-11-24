// Copyright 2026 adesso SE
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

// swift-tools-version: 6.2

import CompilerPluginSupport
import PackageDescription

let package = Package(
    name: "KeyManagement",
    platforms: [.iOS("16.4"), .macOS(.v13), .visionOS(.v1)],
    products: [
        .library(
            name: "KeyManagement",
            targets: ["KeyManagement"]
        )
    ],
    dependencies: [
        .package(
            url: "https://github.com/adesso-mobile-open-source/PersistentStorage-swift",
            from: "1.0.3"
        ),
        .package(url: "https://github.com/Matejkob/swift-spyable", from: "0.9.0"),
        .package(url: "https://github.com/swiftlang/swift-syntax.git", from: "601.0.1")
    ],
    targets: [
        .macro(
            name: "KeyManagementMacros",
            dependencies: [
                .product(name: "SwiftCompilerPlugin", package: "swift-syntax"),
                .product(name: "SwiftSyntax", package: "swift-syntax"),
                .product(name: "SwiftSyntaxMacros", package: "swift-syntax")
            ]
        ),
        .target(
            name: "KeyManagement",
            dependencies: [
                .product(name: "PersistentStorage", package: "PersistentStorage-Swift"),
                .product(name: "Spyable", package: "swift-spyable"),
                "KeyManagementMacros"
            ]
        ),
        .testTarget(
            name: "KeyManagementTests",
            dependencies: [ "KeyManagement" ]
        ),
        .testTarget(
            name: "KeyManagementMacrosTests",
            dependencies: [
                "KeyManagementMacros",
                .product(name: "SwiftSyntaxMacros", package: "swift-syntax"),
                .product(name: "SwiftSyntaxMacrosTestSupport", package: "swift-syntax")
            ]
        )
    ]
)
