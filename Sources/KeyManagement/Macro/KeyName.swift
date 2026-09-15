//
//  KeyName.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// Generates a parameterised `name` property for a ``KeyDescriptor`` struct.
///
/// Apply `@KeyName` to a key descriptor struct when the key name must embed one
/// or more runtime values. Each `{placeholder}` in the template becomes a stored
/// property of type `any ``KeyNameParameterStringConvertible```, and the macro
/// synthesises a `name` computed property that interpolates those values.
///
/// ## Single placeholder
///
/// ```swift
/// @KeyName("account/{accountId}/signing")
/// struct AccountSigningKey: PasswordProtectedKey {}
///
/// // Expands to:
/// // struct AccountSigningKey: PasswordProtectedKey {
/// //     public let accountId: any KeyNameParameterStringConvertible
/// //     public var name: String { "account/\(accountId.stringRepresentation)/signing" }
/// // }
///
/// let key = AccountSigningKey(accountId: "user-42")
/// // key.name == "account/user-42/signing"
/// ```
///
/// ## Multiple placeholders
///
/// ```swift
/// @KeyName("{tenantId}/{userId}/encryption")
/// struct TenantUserKey: BiometryAnyProtectedKey {}
///
/// let key = TenantUserKey(tenantId: "acme", userId: "bob")
/// // key.name == "acme/bob/encryption"
/// ```
///
/// ## Static name (no placeholders)
///
/// A template with no `{placeholder}` segments generates only the `name`
/// computed property with no stored properties:
///
/// ```swift
/// @KeyName("global/device/attestation")
/// struct DeviceKey: UnprotectedKey {}
/// ```
///
/// ## Compile-time validation
///
/// The macro emits a compile-time error for:
/// - An empty or whitespace-only template string.
/// - A placeholder whose name is not a valid Swift identifier (e.g. `{123bad}`).
/// - Duplicate placeholder names within the same template.
///
/// ## Supported parameter types
///
/// Out of the box, `String`, `Int`, `UUID`, and any `CustomStringConvertible`
/// type can be used as parameters. For custom types, conform to
/// ``KeyNameParameterStringConvertible``.
@attached(member, names: named(name), arbitrary)
public macro KeyName(_ template: String) = #externalMacro(module: "KeyManagementMacros", type: "KeyNameMacro")
