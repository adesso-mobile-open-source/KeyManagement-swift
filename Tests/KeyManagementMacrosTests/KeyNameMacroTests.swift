//
//  KeyNameMacroTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

#if os(macOS)
import SwiftSyntaxMacros
import SwiftSyntaxMacrosTestSupport
import XCTest

@testable import KeyManagementMacros

final class KeyNameMacroTests: XCTestCase {

    let macros: [String: any Macro.Type] = ["KeyName": KeyNameMacro.self]

    func testSinglePlaceholder() {
        assertMacroExpansion(
            """
            @KeyName("user/{userId}/signing")
            struct UserKey: PasswordProtectedKey {}
            """,
            expandedSource: """
                struct UserKey: PasswordProtectedKey {

                    public let userId: any KeyNameParameterStringConvertible

                    public var name: String {
                        "user/\\(userId.stringRepresentation)/signing"
                    }}
                """,
            macros: macros
        )
    }

    func testNoPlaceholders() {
        assertMacroExpansion(
            """
            @KeyName("static/key")
            struct StaticKey: UnprotectedKey {}
            """,
            expandedSource: """
                struct StaticKey: UnprotectedKey {

                    public var name: String {
                        "static/key"
                    }}
                """,
            macros: macros
        )
    }

    func testMultiplePlaceholders() {
        assertMacroExpansion(
            """
            @KeyName("{org}/{user}")
            struct OrgKey: BiometryAnyProtectedKey {}
            """,
            expandedSource: """
                struct OrgKey: BiometryAnyProtectedKey {

                    public let org: any KeyNameParameterStringConvertible

                    public let user: any KeyNameParameterStringConvertible

                    public var name: String {
                        "\\(org.stringRepresentation)/\\(user.stringRepresentation)"
                    }}
                """,
            macros: macros
        )
    }

    func testEmptyTemplateEmitsDiagnostic() {
        assertMacroExpansion(
            """
            @KeyName("")
            struct EmptyKey: UnprotectedKey {}
            """,
            expandedSource: "struct EmptyKey: UnprotectedKey {}",
            diagnostics: [.init(message: "@KeyName template must not be empty.", line: 1, column: 1)],
            macros: macros
        )
    }

    func testDuplicatePlaceholderEmitsDiagnostic() {
        assertMacroExpansion(
            """
            @KeyName("{id}/foo/{id}")
            struct DuplicateKey: UnprotectedKey {}
            """,
            expandedSource: "struct DuplicateKey: UnprotectedKey {}",
            diagnostics: [
                .init(message: "@KeyName template contains duplicate placeholder names.", line: 1, column: 1)
            ],
            macros: macros
        )
    }

    func testInvalidIdentifierEmitsDiagnostic() {
        assertMacroExpansion(
            """
            @KeyName("{123bad}")
            struct BadKey: UnprotectedKey {}
            """,
            expandedSource: "struct BadKey: UnprotectedKey {}",
            diagnostics: [
                .init(message: "@KeyName placeholder '123bad' is not a valid Swift identifier.", line: 1, column: 1)
            ],
            macros: macros
        )
    }
}
#endif
