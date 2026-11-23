//
//  KeyNameMacro.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import Foundation
import SwiftSyntax
import SwiftSyntaxMacroExpansion
import SwiftSyntaxMacros

public struct KeyNameMacro: MemberMacro {
    public static func expansion(
        of node: AttributeSyntax,
        providingMembersOf _: some DeclGroupSyntax,
        conformingTo _: [TypeSyntax],
        in _: some MacroExpansionContext
    ) throws -> [DeclSyntax] {
        // 1. Extract template string argument.
        guard case let .argumentList(args) = node.arguments, let first = args.first,
              let lit = first.expression.as(StringLiteralExprSyntax.self),
              case let .stringSegment(seg) = lit.segments.first
        else { throw MacroExpansionErrorMessage("@KeyName requires a string literal argument.") }

        let template = seg.content.text

        // 2. Validate non-empty.
        guard !template.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw MacroExpansionErrorMessage("@KeyName template must not be empty.")
        }

        // 3. Parse placeholders.
        let placeholders = Self.placeholders(in: template)

        // 4. Validate identifiers.
        for placeholder in placeholders {
            guard Self.isValidIdentifier(placeholder) else {
                throw MacroExpansionErrorMessage(
                    "@KeyName placeholder '\(placeholder)' is not a valid Swift identifier."
                )
            }
        }

        // 5. Check duplicates.
        guard Set(placeholders).count == placeholders.count else {
            throw MacroExpansionErrorMessage("@KeyName template contains duplicate placeholder names.")
        }

        // 6. Generate stored properties for each placeholder.
        var decls: [DeclSyntax] = placeholders.map { placeholder in
            "public let \(raw: placeholder): any KeyNameParameterStringConvertible"
        }

        // 7. Generate `var name` with interpolation.
        var body = template
        for placeholder in placeholders {
            body = body.replacingOccurrences(
                of: "{\(placeholder)}",
                with: "\\(\(placeholder).stringRepresentation)"
            )
        }
        decls.append("public var name: String { \"\(raw: body)\" }")

        return decls
    }

    static func placeholders(in template: String) -> [String] {
        var result: [String] = []
        var remaining = template[...]
        while let open = remaining.firstIndex(of: "{") {
            let after = remaining.index(after: open)
            guard let close = remaining[after...].firstIndex(of: "}") else { break }

            result.append(String(remaining[after ..< close]))
            remaining = remaining[remaining.index(after: close)...]
        }
        return result
    }

    static func isValidIdentifier(_ identifier: String) -> Bool {
        guard !identifier.isEmpty else { return false }

        let head = CharacterSet.letters.union(.init(charactersIn: "_"))
        let tail = CharacterSet.alphanumerics.union(.init(charactersIn: "_"))
        guard let firstScalar = identifier.unicodeScalars.first, head.contains(firstScalar) else { return false }

        return identifier.unicodeScalars.dropFirst().allSatisfy { tail.contains($0) }
    }
}
