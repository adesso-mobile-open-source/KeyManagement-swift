//
//  BiometryCurrentSetProtectedKey.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// A key protected by the currently enrolled biometric set.
///
/// The Secure Enclave generates the key with access control flags
/// `.biometryCurrentSet | .privateKeyUsage`. The key is **hardware-invalidated**
/// by the Secure Enclave when the enrolled biometrics change — for example, when
/// a new fingerprint is added, an existing fingerprint is removed, or Face ID is
/// re-enrolled.
///
/// ## Enrollment change detection
///
/// Because the Secure Enclave cannot proactively notify your app when the key
/// becomes invalid, you must call
/// ``KeyManager/hasBiometricEnrollmentChanged(for:)`` before every private-key
/// operation. The check is synchronous and never shows any system UI.
///
/// ```swift
/// if try manager.hasBiometricEnrollmentChanged(for: SigningKey()) {
///     try manager.removeKey(SigningKey())
///     // Prompt the user to re-authenticate
/// }
/// let sig = try await manager.sign(payload: data, with: SigningKey(), laContext: nil)
/// ```
///
/// See the full guide in `docs/biometry-current-set.md`.
///
/// ## Enrollment baseline
///
/// The enrollment baseline is stored automatically the first time any write
/// operation auto-creates the key. Calling
/// ``KeyManager/removeKey(_:)-2b3d0`` (the `BiometryCurrentSetProtectedKey`
/// overload) clears the baseline alongside the keychain item.
///
/// ## Authentication
///
/// All private-key operations are isolated to ``KeyManagementActor`` (never the
/// main actor) and accept an optional `laContext: LAContext?` parameter —
/// same semantics as ``BiometryAnyProtectedKey``.
///
/// ## Simulator behaviour
///
/// On the simulator, `KeyManagerImpl` uses `SoftwareKeyStore`. The `laContext`
/// credential is ignored — **no biometric check is performed and the operation
/// always succeeds**. The enrollment baseline is also stored and compared as
/// usual (using `LAContext.evaluatedPolicyDomainState`), but on the simulator
/// this value may always be `nil`, causing ``KeyManager/hasBiometricEnrollmentChanged(for:)``
/// to always return `true`. Run integration tests on a real device for
/// meaningful enrollment-change detection.
public protocol BiometryCurrentSetProtectedKey: KeyDescriptor {}

extension BiometryCurrentSetProtectedKey {
    static var protectionTrait: ProtectionTrait {
        .biometryCurrentSet
    }
}
