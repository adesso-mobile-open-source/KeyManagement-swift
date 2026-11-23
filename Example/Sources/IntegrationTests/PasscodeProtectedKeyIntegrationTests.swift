//
//  PasscodeProtectedKeyIntegrationTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

// PasscodeProtectedKey integration tests.
//
// Protection: devicePasscode | privateKeyUsage
// Auth: device passcode — system UI shown automatically
// Device: real Secure Enclave required
// Human interaction: REQUIRED — enter device PIN/passcode when prompted
//

import CryptoKit
import Foundation
import KeyManagement
import Testing

@Suite("PasscodeProtectedKey — Integration")
@KeyManagementActor
struct PasscodeProtectedKeyIntegrationTests {
    struct PasscodeSigningKey: PasscodeProtectedKey { let name = "integration.passcode.signing" }
    struct PasscodeDecryptKey: PasscodeProtectedKey { let name = "integration.passcode.decrypt" }
    struct PasscodeDeriveKey: PasscodeProtectedKey { let name = "integration.passcode.derive" }

    let manager = KeyManagerImpl(applicationTag: integrationAppTag)

    init() {
        try? manager.removeKey(PasscodeSigningKey())
        try? manager.removeKey(PasscodeDecryptKey())
        try? manager.removeKey(PasscodeDeriveKey())
    }

    // MARK: - sign roundtrip

    @Test
    func `sign produces a verifiable ECDSA signature`() async throws {
        defer { try? manager.removeKey(PasscodeSigningKey()) }
        let payload = Data("Passcode integration payload".utf8)
        let signature = try manager.sign(payload: payload, with: PasscodeSigningKey())
        let publicKey = try P256.Signing.PublicKey(derRepresentation: manager.getPublicKey(PasscodeSigningKey()))
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        #expect(publicKey.isValidSignature(ecdsaSignature, for: payload))
    }

    @Test
    func `Repeated sign calls reuse the same key`() async throws {
        defer { try? manager.removeKey(PasscodeSigningKey()) }
        let payload = Data("hello".utf8)
        _ = try manager.sign(payload: payload, with: PasscodeSigningKey())
        let pub1 = try manager.getPublicKey(PasscodeSigningKey())
        _ = try manager.sign(payload: payload, with: PasscodeSigningKey())
        let pub2 = try manager.getPublicKey(PasscodeSigningKey())
        #expect(pub1 == pub2)
    }

    // MARK: - encrypt / decrypt roundtrip

    @Test
    func `encrypt then decrypt recovers original plaintext`() async throws {
        defer { try? manager.removeKey(PasscodeDecryptKey()) }
        let plaintext = Data("Passcode-protected secret 🔑".utf8)
        _ = try manager.sign(payload: Data("x".utf8), with: PasscodeDecryptKey())
        let ciphertext = try manager.encrypt(data: plaintext, with: PasscodeDecryptKey())
        let recovered = try manager.decrypt(encodedData: ciphertext, with: PasscodeDecryptKey())
        #expect(recovered == plaintext)
    }

    @Test
    func `decrypt with short payload throws invalidPayload`() async throws {
        defer { try? manager.removeKey(PasscodeDecryptKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: PasscodeDecryptKey())
        #expect(throws: DecryptPasscodeError.invalidPayload) {
            try manager.decrypt(encodedData: Data(repeating: 0, count: 81), with: PasscodeDecryptKey())
        }
    }

    // MARK: - deriveSharedSecret roundtrip

    @Test
    func `deriveSharedSecret matches the ephemeral-side computation`() async throws {
        defer { try? manager.removeKey(PasscodeDeriveKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: PasscodeDeriveKey())
        let ephemeralPriv = P256.KeyAgreement.PrivateKey()
        let ourSecret = try manager.deriveSharedSecret(
            with: PasscodeDeriveKey(), publicKey: ephemeralPriv.publicKey.x963Representation
        )
        #expect(ourSecret.count == 32)
        let storedPub = try P256.KeyAgreement.PublicKey(derRepresentation: manager.getPublicKey(PasscodeDeriveKey()))
        let theirSecret = try ephemeralPriv.sharedSecretFromKeyAgreement(with: storedPub).withUnsafeBytes { Data($0) }
        #expect(ourSecret == theirSecret)
    }
}
