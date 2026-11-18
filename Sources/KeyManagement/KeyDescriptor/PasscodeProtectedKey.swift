//
//  PasscodeProtectedKey.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// A key protected by the device passcode.
///
/// The Secure Enclave generates the key with access control flags
/// `.devicePasscode | .privateKeyUsage`. The system presents its own passcode
/// entry UI automatically; your code does not supply any credential parameter.
///
/// ## Authentication
///
/// Private-key operations (`create`, `sign`, `deriveSharedSecret`, `decrypt`)
/// take no credential parameter. The system UI is shown by the Security
/// framework internally. These calls block the calling thread for as long as
/// the passcode prompt is on screen — exactly like biometric authentication —
/// so they are isolated to ``KeyManagementActor`` (never the main actor). Call
/// them with `await`. `encrypt` is the exception: it only uses the public key,
/// requires no authentication, and remains synchronous.
///
/// ## Simulator behaviour
///
/// On the simulator, `KeyManagerImpl` uses `SoftwareKeyStore`. The passcode
/// credential is handled as `.none` — **no passcode check is performed and the
/// operation always succeeds without any system UI**. This lets you exercise
/// the call flow on the simulator, but provides no security guarantee. Run
/// integration tests on a real device to verify actual passcode authentication.
///
/// ## Example
///
/// ```swift
/// struct PasscodeKey: PasscodeProtectedKey {
///     let name = "com.example.app.passcode"
/// }
///
/// // System shows passcode UI automatically. `sign` is isolated to
/// // KeyManagementActor, so it must be awaited.
/// let sig = try await manager.sign(payload: data, with: PasscodeKey())
/// ```
public protocol PasscodeProtectedKey: KeyDescriptor {}

extension PasscodeProtectedKey {
    static var protectionTrait: ProtectionTrait {
        .passcode
    }
}
