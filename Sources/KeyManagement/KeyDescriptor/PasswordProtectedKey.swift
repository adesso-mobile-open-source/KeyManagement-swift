//
//  PasswordProtectedKey.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// A key whose private-key operations require an application-supplied password.
///
/// The Secure Enclave generates the key with access control flags
/// `.applicationPassword | .privateKeyUsage`. Every private-key operation
/// (`sign`, `deriveSharedSecret`, `decrypt`) must supply the correct
/// `password: Data` parameter. The password is set on an `LAContext` and
/// presented to the Secure Enclave; the validation happens in hardware without
/// any visible system UI.
///
/// ## Device support
///
/// `PasswordProtectedKey` is the only trait that works on both the simulator
/// and a real device. On the simulator, `KeyManagerImpl` uses a software key
/// store; the password check is a byte-equality comparison in software.
///
/// ## Example
///
/// ```swift
/// struct AppSigningKey: PasswordProtectedKey {
///     let name = "com.example.app.signing"
/// }
///
/// let password = Data("s3cr3t".utf8)
/// let sig = try manager.sign(payload: data, with: AppSigningKey(), password: password)
/// ```
public protocol PasswordProtectedKey: KeyDescriptor { }

extension PasswordProtectedKey {
    static var protectionTrait: ProtectionTrait {
        .password
    }
}
