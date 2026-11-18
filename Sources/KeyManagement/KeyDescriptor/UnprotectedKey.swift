//
//  UnprotectedKey.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// A key with no access control protection.
///
/// The Secure Enclave generates the key with the `privateKeyUsage` flag only —
/// no authentication is required to use the private key. Because the key is
/// still generated inside the Secure Enclave and never leaves the hardware, it
/// proves *device possession* without requiring the user to authenticate.
///
/// ## Security considerations
///
/// Any code that can run on the device can perform private-key operations with
/// this key. Use this trait only when **device possession alone** is a sufficient
/// security guarantee — for example, a device-attestation flow where the server
/// verifies that a specific device is enrolled, without requiring the user to
/// authenticate.
///
/// > Warning: Do not use `UnprotectedKey` for operations that protect
/// > user-specific data or require proof of user intent.
///
/// ## Device requirements
///
/// Requires a real iOS device with a Secure Enclave. Cannot be tested on the
/// simulator.
///
/// ## Example
///
/// ```swift
/// struct DeviceAttestationKey: UnprotectedKey {
///     let name = "com.example.app.deviceattestation"
/// }
///
/// let sig = try manager.sign(payload: challenge, with: DeviceAttestationKey())
/// ```
public protocol UnprotectedKey: KeyDescriptor {}

extension UnprotectedKey {
    static var protectionTrait: ProtectionTrait {
        .unprotected
    }
}
