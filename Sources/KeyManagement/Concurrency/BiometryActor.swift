//
//  BiometryActor.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// A global actor that isolates Secure Enclave operations for biometry-gated
/// keys.
///
/// ``BiometryAnyProtectedKey``, ``BiometryCurrentSetProtectedKey``, and
/// ``UserPresenceProtectedKey`` operations call into `Security` framework
/// functions (`SecItemCopyMatching`, `SecKeyCreateSignature`,
/// `SecKeyCopyKeyExchangeResult`, `SecKeyCreateDecryptedData`, …) with an
/// access-control object that requires Face ID, Touch ID, or device passcode
/// authentication. **These calls block the calling thread for as long as the
/// biometric/passcode prompt is on screen.** Apple's own documentation for
/// `SecAccessControlCreateWithFlags` warns explicitly against performing them
/// on the main thread:
///
/// > "Accessing keychain items or performing operations on keys which are
/// > protected by access control objects can block the execution because of
/// > UI which can appear to satisfy the access control conditions, therefore
/// > it is recommended to either move those potentially blocking operations
/// > out of the main application thread […]"
///
/// `BiometryActor` gives these operations a dedicated, serial execution
/// context that is guaranteed **not** to be the main thread. Isolating them
/// to `MainActor` instead — as earlier versions of this library did — would
/// block the main thread (and therefore all UI updates, animations, and
/// input handling) for the entire duration of the system authentication
/// prompt, and risks a watchdog termination on slow biometric evaluations.
///
/// All `create`, `sign`, `deriveSharedSecret`, and `decrypt` overloads for
/// ``BiometryAnyProtectedKey``, ``BiometryCurrentSetProtectedKey``, and
/// ``UserPresenceProtectedKey`` are isolated to this actor. Call them with
/// `await` from any context — Swift automatically hops to `BiometryActor`
/// for you; there is nothing further you need to do unless you also want to
/// isolate your own surrounding code to it.
///
/// ```swift
/// // From any actor / task — the call hops to BiometryActor automatically
/// // and runs off the main thread.
/// let signature = try await manager.sign(payload: data, with: MyBiometricKey(), laContext: nil)
/// ```
@globalActor
public actor BiometryActor {
    public static let shared = BiometryActor()
}
