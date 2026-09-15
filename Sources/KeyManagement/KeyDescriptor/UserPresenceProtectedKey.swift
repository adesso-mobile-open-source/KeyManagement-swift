//
//  UserPresenceProtectedKey.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// A key protected by user presence: Touch ID, Face ID, or passcode fallback.
///
/// The Secure Enclave generates the key with access control flags
/// `.userPresence | .privateKeyUsage`. The system first attempts biometric
/// authentication; if biometry is unavailable or fails, it falls back to the
/// device passcode. This provides the most permissive authentication experience
/// among the biometric traits.
///
/// ## Authentication
///
/// All private-key operations are isolated to ``BiometryActor`` (never the
/// main actor) and accept an optional
/// `laContext: LAContext?` parameter:
///
/// - Pass `nil` to let the system decide and show the appropriate prompt.
/// - Pass a pre-evaluated `LAContext` obtained via
///   `.deviceOwnerAuthentication` to reuse a previous authentication.
///
/// ## Comparison with other biometric traits
///
/// | Trait | Invalidated by biometric changes | Passcode fallback |
/// |---|---|---|
/// | ``BiometryAnyProtectedKey`` | No | No |
/// | ``BiometryCurrentSetProtectedKey`` | Yes | No |
/// | ``UserPresenceProtectedKey`` | No | Yes |
///
/// ## Simulator behaviour
///
/// On the simulator, `KeyManagerImpl` uses `SoftwareKeyStore`. The `laContext`
/// credential is ignored — **no biometric or passcode check is performed and
/// the operation always succeeds**. Run integration tests on a real device to
/// verify actual user-presence authentication.
///
/// ## Example
///
/// ```swift
/// struct PresenceKey: UserPresenceProtectedKey {
///     let name = "com.example.app.presence"
/// }
///
/// let sig = try await manager.sign(payload: data, with: PresenceKey(), laContext: nil)
/// ```
public protocol UserPresenceProtectedKey: KeyDescriptor {}

extension UserPresenceProtectedKey {
    static var protectionTrait: ProtectionTrait {
        .userPresence
    }
}
