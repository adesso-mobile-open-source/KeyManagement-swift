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
/// Private-key operations (`sign`, `deriveSharedSecret`, `decrypt`) take no
/// credential parameter. The system UI is shown by the Security framework
/// internally.
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
/// // System shows passcode UI automatically
/// let sig = try manager.sign(payload: data, with: PasscodeKey())
/// ```
public protocol PasscodeProtectedKey: KeyDescriptor {}

extension PasscodeProtectedKey {
    static var protectionTrait: ProtectionTrait {
        .passcode
    }
}
