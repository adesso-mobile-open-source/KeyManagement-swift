//
//  BiometryAnyProtectedKeyIntegrationTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

// BiometryAnyProtectedKey integration tests.
//
// Protection: biometryAny | privateKeyUsage
// Auth: Face ID / Touch ID (any enrolled) — HUMAN MUST AUTHENTICATE
// Device: real Secure Enclave required
// Human interaction: REQUIRED — accept Face ID / Touch ID prompt
//
import CryptoKit
import KeyManagement
import LocalAuthentication
import Testing

@Suite("BiometryAnyProtectedKey — Integration")
struct BiometryAnyProtectedKeyIntegrationTests {

    struct BiometrySigningKey: BiometryAnyProtectedKey { let name = "integration.biometryAny.signing" }
    struct BiometryDeriveKey: BiometryAnyProtectedKey { let name = "integration.biometryAny.derive" }
    struct BiometryDecryptKey: BiometryAnyProtectedKey { let name = "integration.biometryAny.decrypt" }

    let manager = KeyManagerImpl(applicationTag: integrationAppTag)

    init() {
        try? manager.removeKey(BiometrySigningKey())
        try? manager.removeKey(BiometryDeriveKey())
        try? manager.removeKey(BiometryDecryptKey())
    }

    @BiometryActor
    private func evaluatedContext(reason: String) async throws -> LAContext {
        let ctx = LAContext()
        try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        return ctx
    }

    // MARK: - sign roundtrip

    @Test("sign produces a verifiable ECDSA signature")
    @BiometryActor
    func sign_producesVerifiableSignature() async throws {
        defer { try? manager.removeKey(BiometrySigningKey()) }
        let payload = Data("Integration test payload".utf8)
        let ctx = try await evaluatedContext(reason: "Sign — BiometryAny integration test")
        let signature = try manager.sign(payload: payload, with: BiometrySigningKey(), laContext: ctx)
        let publicKey = try P256.Signing.PublicKey(derRepresentation: manager.getPublicKey(BiometrySigningKey()))
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        #expect(publicKey.isValidSignature(ecdsaSignature, for: payload))
    }

    @Test("Repeated sign calls reuse the same key")
    @BiometryActor
    func sign_secondCallReusesKey() async throws {
        defer { try? manager.removeKey(BiometrySigningKey()) }
        let payload = Data("hello".utf8)
        let ctx1 = try await evaluatedContext(reason: "First sign — BiometryAny")
        _ = try manager.sign(payload: payload, with: BiometrySigningKey(), laContext: ctx1)
        let pub1 = try manager.getPublicKey(BiometrySigningKey())
        let ctx2 = try await evaluatedContext(reason: "Second sign — BiometryAny")
        _ = try manager.sign(payload: payload, with: BiometrySigningKey(), laContext: ctx2)
        let pub2 = try manager.getPublicKey(BiometrySigningKey())
        #expect(pub1 == pub2)
    }

    // MARK: - encrypt / decrypt roundtrip

    @Test("encrypt then decrypt recovers original plaintext")
    @BiometryActor
    func encrypt_decrypt_roundtrip() async throws {
        defer { try? manager.removeKey(BiometryDecryptKey()) }
        let plaintext = Data("Biometry-protected secret 🔑".utf8)
        let ctx1 = try await evaluatedContext(reason: "Create key — BiometryAny")
        _ = try manager.sign(payload: Data("x".utf8), with: BiometryDecryptKey(), laContext: ctx1)
        let ciphertext = try manager.encrypt(data: plaintext, with: BiometryDecryptKey())
        let ctx2 = try await evaluatedContext(reason: "Decrypt — BiometryAny")
        let recovered = try manager.decrypt(encodedData: ciphertext, with: BiometryDecryptKey(), laContext: ctx2)
        #expect(recovered == plaintext)
    }

    @Test("decrypt with short payload throws invalidPayload without prompting")
    @BiometryActor
    func decrypt_shortPayloadThrowsInvalidPayload() throws {
        defer { try? manager.removeKey(BiometryDecryptKey()) }
        #expect(throws: DecryptBiometryAnyError.invalidPayload) {
            try manager.decrypt(encodedData: Data(repeating: 0, count: 81), with: BiometryDecryptKey(), laContext: nil)
        }
    }

    // MARK: - deriveSharedSecret roundtrip

    @Test("deriveSharedSecret matches the ephemeral-side computation")
    @BiometryActor
    func deriveSharedSecret_matchesEphemeralSide() async throws {
        defer { try? manager.removeKey(BiometryDeriveKey()) }
        let ctx1 = try await evaluatedContext(reason: "Create key — BiometryAny")
        _ = try manager.sign(payload: Data("x".utf8), with: BiometryDeriveKey(), laContext: ctx1)
        let ephemeralPriv = P256.KeyAgreement.PrivateKey()
        let ctx2 = try await evaluatedContext(reason: "Derive shared secret — BiometryAny")
        let ourSecret = try manager.deriveSharedSecret(
            with: BiometryDeriveKey(), publicKey: ephemeralPriv.publicKey.x963Representation, laContext: ctx2
        )
        #expect(ourSecret.count == 32)
        let storedPub = try P256.KeyAgreement.PublicKey(derRepresentation: manager.getPublicKey(BiometryDeriveKey()))
        let theirSecret = try ephemeralPriv.sharedSecretFromKeyAgreement(with: storedPub).withUnsafeBytes { Data($0) }
        #expect(ourSecret == theirSecret)
    }
}
