//
//  UserPresenceProtectedKeyIntegrationTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

// UserPresenceProtectedKey integration tests.
//
// Protection: userPresence | privateKeyUsage
// Auth: Face ID / Touch ID with passcode fallback — HUMAN MUST AUTHENTICATE
// Device: real Secure Enclave required
// Human interaction: REQUIRED — accept biometric or enter passcode
//
import CryptoKit
import KeyManagement
import LocalAuthentication
import Testing

@Suite("UserPresenceProtectedKey — Integration")
@KeyManagementActor
struct UserPresenceProtectedKeyIntegrationTests {

    struct UserPresenceSigningKey: UserPresenceProtectedKey { let name = "integration.userPresence.signing" }
    struct UserPresenceDecryptKey: UserPresenceProtectedKey { let name = "integration.userPresence.decrypt" }
    struct UserPresenceDeriveKey: UserPresenceProtectedKey { let name = "integration.userPresence.derive" }

    let manager = KeyManagerImpl(applicationTag: integrationAppTag)

    init() {
        try? manager.removeKey(UserPresenceSigningKey())
        try? manager.removeKey(UserPresenceDecryptKey())
        try? manager.removeKey(UserPresenceDeriveKey())
    }

    private func evaluatedContext(reason: String) async throws -> LAContext {
        let ctx = LAContext()
        try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        return ctx
    }

    // MARK: - sign roundtrip

    @Test("sign produces a verifiable ECDSA signature")
    func sign_producesVerifiableSignature() async throws {
        defer { try? manager.removeKey(UserPresenceSigningKey()) }
        let payload = Data("UserPresence integration payload".utf8)
        let ctx = try await evaluatedContext(reason: "Sign — UserPresence integration test")
        let signature = try manager.sign(payload: payload, with: UserPresenceSigningKey(), laContext: ctx)
        let publicKey = try P256.Signing.PublicKey(derRepresentation: manager.getPublicKey(UserPresenceSigningKey()))
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        #expect(publicKey.isValidSignature(ecdsaSignature, for: payload))
    }

    // MARK: - encrypt / decrypt roundtrip

    @Test("encrypt then decrypt recovers original plaintext")
    func encrypt_decrypt_roundtrip() async throws {
        defer { try? manager.removeKey(UserPresenceDecryptKey()) }
        let plaintext = Data("UserPresence secret 🔑".utf8)
        let ctx1 = try await evaluatedContext(reason: "Create key — UserPresence")
        _ = try manager.sign(payload: Data("x".utf8), with: UserPresenceDecryptKey(), laContext: ctx1)
        let ciphertext = try manager.encrypt(data: plaintext, with: UserPresenceDecryptKey())
        let ctx2 = try await evaluatedContext(reason: "Decrypt — UserPresence")
        let recovered = try manager.decrypt(encodedData: ciphertext, with: UserPresenceDecryptKey(), laContext: ctx2)
        #expect(recovered == plaintext)
    }

    @Test("decrypt with short payload throws invalidPayload without prompting")
    func decrypt_shortPayloadThrowsInvalidPayload() throws {
        defer { try? manager.removeKey(UserPresenceDecryptKey()) }
        #expect(throws: DecryptUserPresenceError.invalidPayload) {
            try manager.decrypt(
                encodedData: Data(repeating: 0, count: 81),
                with: UserPresenceDecryptKey(),
                laContext: nil
            )
        }
    }

    // MARK: - deriveSharedSecret roundtrip

    @Test("deriveSharedSecret matches the ephemeral-side computation")
    func deriveSharedSecret_matchesEphemeralSide() async throws {
        defer { try? manager.removeKey(UserPresenceDeriveKey()) }
        let ctx1 = try await evaluatedContext(reason: "Create key — UserPresence derive")
        _ = try manager.sign(payload: Data("x".utf8), with: UserPresenceDeriveKey(), laContext: ctx1)
        let ephemeralPriv = P256.KeyAgreement.PrivateKey()
        let ctx2 = try await evaluatedContext(reason: "Derive shared secret — UserPresence")
        let ourSecret = try manager.deriveSharedSecret(
            with: UserPresenceDeriveKey(), publicKey: ephemeralPriv.publicKey.x963Representation, laContext: ctx2
        )
        #expect(ourSecret.count == 32)
        let storedPub = try P256.KeyAgreement.PublicKey(
            derRepresentation: manager.getPublicKey(UserPresenceDeriveKey())
        )
        let theirSecret = try ephemeralPriv.sharedSecretFromKeyAgreement(with: storedPub).withUnsafeBytes { Data($0) }
        #expect(ourSecret == theirSecret)
    }
}
