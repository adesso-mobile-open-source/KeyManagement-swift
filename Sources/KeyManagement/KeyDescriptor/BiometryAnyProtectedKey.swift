//
//  BiometryAnyProtectedKey.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// A key protected by Touch ID (any enrolled finger) or Face ID.
///
/// The Secure Enclave generates the key with access control flags
/// `.biometryAny | .privateKeyUsage`. The key remains valid if new biometrics
/// are added or Face ID is re-enrolled — it is only invalidated when **all**
/// biometrics are reset on the device.
///
/// ## Authentication
///
/// All private-key operations are isolated to ``BiometryActor`` (never the
/// main actor) and accept an optional
/// `laContext: LAContext?` parameter:
///
/// - Pass `nil` to let the system show a biometric prompt automatically.
/// - Pass a pre-evaluated `LAContext` to reuse an authentication context that
///   you obtained earlier (for example, to avoid a second prompt within the same
///   user interaction).
///
/// ## Simulator behaviour
///
/// On the simulator, `KeyManagerImpl` uses `SoftwareKeyStore` instead of the
/// Secure Enclave. `SoftwareKeyStore` ignores the `laContext` credential
/// entirely: **no biometric check is performed and the operation always
/// succeeds**. This lets you exercise your application flow on the simulator
/// without hardware, but it provides no security guarantee. Run integration
/// tests on a real device to verify actual biometric authentication.
///
/// ## Example
///
/// ```swift
/// struct BiometricKey: BiometryAnyProtectedKey {
///     let name = "com.example.app.biometric"
/// }
///
/// // System presents a biometric prompt. `await` hops to `BiometryActor`
/// // so the call runs off the main thread.
/// let sig = try await manager.sign(payload: data, with: BiometricKey(), laContext: nil)
/// ```
public protocol BiometryAnyProtectedKey: KeyDescriptor {}

extension BiometryAnyProtectedKey {
    static var protectionTrait: ProtectionTrait {
        .biometryAny
    }
}
