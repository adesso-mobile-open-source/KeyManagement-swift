//
//  KeyDescriptor.swift
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

/// The base protocol every key configuration struct must conform to.
///
/// A ``KeyDescriptor`` is a lightweight, stateless value type that identifies a
/// key by name and specifies its device-level accessibility class. It does **not**
/// carry runtime secrets such as passwords or `LAContext` references — those appear
/// as parameters on the individual ``KeyManager`` methods.
///
/// ## Defining a key
///
/// Conform a plain `struct` to one of the six trait protocols. Both requirements
/// have default implementations, so an empty struct is valid:
///
/// ```swift
/// struct AppSigningKey: PasswordProtectedKey {}
/// // name → "AppSigningKey", protectionMode → .whenUnlockedThisDeviceOnly
/// ```
///
/// Override either default when needed:
///
/// ```swift
/// struct AppSigningKey: PasswordProtectedKey {
///     let name = "com.example.app.signing"
///     let protectionMode: ProtectionMode = .whenUnlockedThisDeviceOnly
/// }
/// ```
///
/// ## Parameterised names
///
/// Use the ``KeyName(_:)`` macro when the name must embed runtime values:
///
/// ```swift
/// @KeyName("account/{accountId}/signing")
/// struct AccountSigningKey: PasswordProtectedKey {}
///
/// let key = AccountSigningKey(accountId: "user-42")
/// // key.name == "account/user-42/signing"
/// ```
///
/// ## Key uniqueness
///
/// Keys are identified by their ``name`` within a single `KeyManagerImpl` instance.
/// Two descriptors with the same name and same trait share the same underlying
/// keychain item. Two descriptors with the same name but **different** traits will
/// cause ``KeyManager`` to throw a `configurationMismatch` error.
public protocol KeyDescriptor: Sendable {
    /// The unique identifier for this key within the keystore.
    ///
    /// The name is combined with the `applicationTag` supplied to
    /// ``KeyManagerImpl/init(applicationTag:)`` to form the keychain application
    /// tag: `"\(applicationTag).\(name)"`.
    ///
    /// Names must be unique across all keys managed by the same
    /// ``KeyManagerImpl`` instance. Keys with the same name but different trait
    /// protocols produce a ``SignPasswordError/configurationMismatch(name:)``
    /// (or the trait-specific equivalent) when a mismatch is detected.
    ///
    /// The default implementation returns the unqualified Swift type name of the
    /// conforming type — for example, a struct named `AppSigningKey` gets the
    /// name `"AppSigningKey"`. Override this property to use a stable, namespaced
    /// string that is independent of your type names.
    var name: String { get }

    /// The device-level accessibility class for the keychain item backing this key.
    ///
    /// Controls *when* the operating system allows access to the key's keychain
    /// item. The default value is ``ProtectionMode/whenUnlockedThisDeviceOnly``,
    /// which prevents migration to other devices and requires the device to be
    /// unlocked. Override only when you have a specific requirement — for example,
    /// a background task that must access a key while the device is locked would
    /// use ``ProtectionMode/afterFirstUnlockThisDeviceOnly``.
    var protectionMode: ProtectionMode { get }
}

public extension KeyDescriptor {
    /// Returns the unqualified Swift type name of the conforming type.
    ///
    /// For example, a struct named `MySigningKey` returns `"MySigningKey"`.
    ///
    /// > Warning: This default is **not safe for production use**. If you rename
    /// > the struct, the name silently changes and any key previously stored under
    /// > the old name becomes permanently inaccessible. Always override `name`
    /// > with a stable, namespaced string literal that will never change:
    /// > ```swift
    /// > struct AppSigningKey: PasswordProtectedKey {
    /// >     let name = "com.example.app.signing" // stable, independent of type name
    /// > }
    /// > ```
    var name: String { String(describing: Self.self) }

    /// Returns ``ProtectionMode/whenUnlockedThisDeviceOnly``.
    ///
    /// This default prevents the key from migrating to other devices and requires
    /// the device to be unlocked before the key can be accessed. Override when
    /// your use case requires different accessibility semantics.
    var protectionMode: ProtectionMode { .whenUnlockedThisDeviceOnly }
}
