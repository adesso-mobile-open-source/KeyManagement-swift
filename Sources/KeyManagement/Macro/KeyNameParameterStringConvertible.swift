//
//  KeyNameParameterStringConvertible.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import Foundation

/// A type whose value can appear as a segment in a ``KeyName(_:)`` template.
///
/// Types that conform to this protocol can be used as parameters in a
/// `@KeyName` template. The ``stringRepresentation`` property is called at
/// runtime to build the key's `name` string.
///
/// ## Built-in conformances
///
/// The library provides conformances for the most common types:
///
/// | Type | `stringRepresentation` |
/// |------|------------------------|
/// | `String` | The string value itself |
/// | `Int` | The decimal string representation |
/// | `UUID` | `uuidString` (upper-case, hyphenated) |
/// | Any `CustomStringConvertible` | `description` |
///
/// ## Custom types
///
/// Conform your own type when you need a specific string format:
///
/// ```swift
/// struct UserID: KeyNameParameterStringConvertible {
///     let value: Int
///     var stringRepresentation: String { "user-\(value)" }
/// }
///
/// @KeyName("account/{userId}/signing")
/// struct AccountKey: PasswordProtectedKey {}
///
/// let key = AccountKey(userId: UserID(value: 42))
/// // key.name == "account/user-42/signing"
/// ```
public protocol KeyNameParameterStringConvertible: Sendable {
    /// The string segment to embed in the key name.
    ///
    /// This value is interpolated into the key name at runtime each time
    /// the `name` property is read. It must not contain path-separator
    /// characters that are meaningful to your key-naming scheme.
    var stringRepresentation: String { get }
}

public extension KeyNameParameterStringConvertible where Self: CustomStringConvertible {
    /// Returns `description`, satisfying ``stringRepresentation`` for any
    /// `CustomStringConvertible` type.
    var stringRepresentation: String { description }
}

extension String: KeyNameParameterStringConvertible { }
extension Int: KeyNameParameterStringConvertible { }
extension UUID: KeyNameParameterStringConvertible {
    /// Returns `uuidString` — the standard hyphenated upper-case UUID string.
    public var stringRepresentation: String { uuidString }
}
