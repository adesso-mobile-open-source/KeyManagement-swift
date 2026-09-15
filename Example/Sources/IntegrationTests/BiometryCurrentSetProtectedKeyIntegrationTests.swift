//
//  BiometryCurrentSetProtectedKeyIntegrationTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

// BiometryCurrentSetProtectedKey integration tests.
//
// Protection: biometryCurrentSet | privateKeyUsage
// Auth: currently enrolled Face ID / Touch ID — HUMAN MUST AUTHENTICATE
// Device: real Secure Enclave required
// Human interaction: REQUIRED — accept Face ID / Touch ID prompt
//
import CryptoKit
import KeyManagement
import LocalAuthentication
import Testing

@Suite("BiometryCurrentSetProtectedKey — Integration")
struct BiometryCurrentSetKeyIntegrationTests {

    struct CurrentSetSigningKey: BiometryCurrentSetProtectedKey { let name = "integration.biometryCurrentSet.signing" }
    struct CurrentSetDecryptKey: BiometryCurrentSetProtectedKey { let name = "integration.biometryCurrentSet.decrypt" }
    struct CurrentSetDeriveKey: BiometryCurrentSetProtectedKey { let name = "integration.biometryCurrentSet.derive" }

    let manager = KeyManagerImpl(applicationTag: integrationAppTag)

    init() {
        try? manager.removeKey(CurrentSetSigningKey())
        try? manager.removeKey(CurrentSetDecryptKey())
        try? manager.removeKey(CurrentSetDeriveKey())
    }

    @BiometryActor
    private func evaluatedContext(reason: String) async throws -> LAContext {
        let ctx = LAContext()
        try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        return ctx
    }

    // MARK: - Enrollment change detection (prompt-free)

    @Test("hasBiometricEnrollmentChanged returns true before any create (no baseline)")
    func enrollmentChanged_trueWithNoBaseline() throws {
        #expect(try manager.hasBiometricEnrollmentChanged(for: CurrentSetSigningKey()) == true)
    }

    @Test("hasBiometricEnrollmentChanged returns false immediately after auto-create")
    @BiometryActor
    func enrollmentChanged_falseAfterAutoCreate() async throws {
        defer { try? manager.removeKey(CurrentSetSigningKey()) }
        let ctx = try await evaluatedContext(reason: "Create key — BiometryCurrentSet enrollment check")
        _ = try manager.sign(payload: Data("x".utf8), with: CurrentSetSigningKey(), laContext: ctx)
        #expect(try manager.hasBiometricEnrollmentChanged(for: CurrentSetSigningKey()) == false)
    }

    @Test("hasBiometricEnrollmentChanged returns true after removeKey clears baseline")
    @BiometryActor
    func enrollmentChanged_trueAfterRemoveKey() async throws {
        let ctx = try await evaluatedContext(reason: "Create key — BiometryCurrentSet remove baseline")
        _ = try manager.sign(payload: Data("x".utf8), with: CurrentSetSigningKey(), laContext: ctx)
        try manager.removeKey(CurrentSetSigningKey())
        #expect(try manager.hasBiometricEnrollmentChanged(for: CurrentSetSigningKey()) == true)
    }

    // MARK: - sign roundtrip

    @Test("sign produces a verifiable ECDSA signature")
    @BiometryActor
    func sign_producesVerifiableSignature() async throws {
        defer { try? manager.removeKey(CurrentSetSigningKey()) }
        let payload = Data("CurrentSet integration payload".utf8)
        let ctx = try await evaluatedContext(reason: "Sign — BiometryCurrentSet")
        let signature = try manager.sign(payload: payload, with: CurrentSetSigningKey(), laContext: ctx)
        let publicKey = try P256.Signing.PublicKey(derRepresentation: manager.getPublicKey(CurrentSetSigningKey()))
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        #expect(publicKey.isValidSignature(ecdsaSignature, for: payload))
    }

    // MARK: - encrypt / decrypt roundtrip

    @Test("encrypt then decrypt recovers original plaintext")
    @BiometryActor
    func encrypt_decrypt_roundtrip() async throws {
        defer { try? manager.removeKey(CurrentSetDecryptKey()) }
        let plaintext = Data("CurrentSet secret 🔐".utf8)
        let ctx1 = try await evaluatedContext(reason: "Create key — BiometryCurrentSet")
        _ = try manager.sign(payload: Data("x".utf8), with: CurrentSetDecryptKey(), laContext: ctx1)
        let ciphertext = try manager.encrypt(data: plaintext, with: CurrentSetDecryptKey())
        let ctx2 = try await evaluatedContext(reason: "Decrypt — BiometryCurrentSet")
        let recovered = try manager.decrypt(encodedData: ciphertext, with: CurrentSetDecryptKey(), laContext: ctx2)
        #expect(recovered == plaintext)
    }

    @Test("decrypt with short payload throws invalidPayload without prompting")
    @BiometryActor
    func decrypt_shortPayloadThrowsInvalidPayload() throws {
        defer { try? manager.removeKey(CurrentSetDecryptKey()) }
        #expect(throws: DecryptBiometryCurrentSetError.invalidPayload) {
            try manager.decrypt(
                encodedData: Data(repeating: 0, count: 81),
                with: CurrentSetDecryptKey(),
                laContext: nil
            )
        }
    }

    // MARK: - deriveSharedSecret roundtrip

    @Test("deriveSharedSecret matches the ephemeral-side computation")
    @BiometryActor
    func deriveSharedSecret_matchesEphemeralSide() async throws {
        defer { try? manager.removeKey(CurrentSetDeriveKey()) }
        let ctx1 = try await evaluatedContext(reason: "Create key — BiometryCurrentSet derive")
        _ = try manager.sign(payload: Data("x".utf8), with: CurrentSetDeriveKey(), laContext: ctx1)
        let ephemeralPriv = P256.KeyAgreement.PrivateKey()
        let ctx2 = try await evaluatedContext(reason: "Derive shared secret — BiometryCurrentSet")
        let ourSecret = try manager.deriveSharedSecret(
            with: CurrentSetDeriveKey(), publicKey: ephemeralPriv.publicKey.x963Representation, laContext: ctx2
        )
        #expect(ourSecret.count == 32)
        let storedPub = try P256.KeyAgreement.PublicKey(derRepresentation: manager.getPublicKey(CurrentSetDeriveKey()))
        let theirSecret = try ephemeralPriv.sharedSecretFromKeyAgreement(with: storedPub).withUnsafeBytes { Data($0) }
        #expect(ourSecret == theirSecret)
    }
}
