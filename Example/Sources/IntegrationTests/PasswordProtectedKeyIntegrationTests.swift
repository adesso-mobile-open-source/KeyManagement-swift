//
//  PasswordProtectedKeyIntegrationTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

// PasswordProtectedKey integration tests.
//
// Protection: applicationPassword | privateKeyUsage
// Auth: caller-supplied Data password
// Device: real Secure Enclave required
// Human interaction: NONE (password is software-supplied)
//

import CryptoKit
import Foundation
import KeyManagement
import Testing

@Suite("PasswordProtectedKey — Integration")
struct PasswordProtectedKeyIntegrationTests {

    // MARK: - Key descriptors

    struct AppSigningKey: PasswordProtectedKey { let name = "integration.password.signing" }
    struct AppDeriveKey: PasswordProtectedKey { let name = "integration.password.derive" }
    struct AppDecryptKey: PasswordProtectedKey { let name = "integration.password.decrypt" }

    // MARK: - State

    let manager = KeyManagerImpl(applicationTag: integrationAppTag)
    let password      = Data("correct-horse-battery-staple".utf8)
    let wrongPassword = Data("wrong".utf8)

    init() {
        try? manager.removeKey(AppSigningKey())
        try? manager.removeKey(AppDeriveKey())
        try? manager.removeKey(AppDecryptKey())
    }

    // MARK: - hasKey / removeKey

    @Test("hasKey returns false before first write")
    func hasKey_returnsFalseBeforeCreate() throws {
        defer { try? manager.removeKey(AppSigningKey()) }
        #expect(try manager.hasKey(AppSigningKey()) == false)
    }

    @Test("hasKey returns true after auto-create via sign")
    func hasKey_returnsTrueAfterAutoCreate() throws {
        defer { try? manager.removeKey(AppSigningKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: AppSigningKey(), password: password)
        #expect(try manager.hasKey(AppSigningKey()) == true)
    }

    @Test("removeKey clears the key")
    func removeKey_clearsKey() throws {
        _ = try manager.sign(payload: Data("x".utf8), with: AppSigningKey(), password: password)
        try manager.removeKey(AppSigningKey())
        #expect(try manager.hasKey(AppSigningKey()) == false)
    }

    // MARK: - getPublicKey

    @Test("getPublicKey throws keyNotFound before first write")
    func getPublicKey_throwsKeyNotFoundBeforeCreate() throws {
        defer { try? manager.removeKey(AppSigningKey()) }
        #expect(throws: GetPublicKeyError.keyNotFound(name: AppSigningKey().name)) {
            try manager.getPublicKey(AppSigningKey())
        }
    }

    @Test("getPublicKey returns 91-byte DER-encoded P-256 key")
    func getPublicKey_returnsDER() throws {
        defer { try? manager.removeKey(AppSigningKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: AppSigningKey(), password: password)
        let pub = try manager.getPublicKey(AppSigningKey())
        #expect(pub.first == 0x30)
        #expect(pub.count == 91)
    }

    // MARK: - sign roundtrip

    @Test("sign produces a verifiable ECDSA signature")
    func sign_producesVerifiableSignature() throws {
        defer { try? manager.removeKey(AppSigningKey()) }
        let payload = Data("The quick brown fox".utf8)
        let signature = try manager.sign(payload: payload, with: AppSigningKey(), password: password)
        let publicKey = try P256.Signing.PublicKey(derRepresentation: manager.getPublicKey(AppSigningKey()))
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        #expect(publicKey.isValidSignature(ecdsaSignature, for: payload))
    }

    @Test("sign with wrong password throws invalidPassword")
    func sign_wrongPasswordThrowsInvalidPassword() throws {
        defer { try? manager.removeKey(AppSigningKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: AppSigningKey(), password: password)
        #expect(throws: SignPasswordError.invalidPassword(name: AppSigningKey().name)) {
            try manager.sign(payload: Data("x".utf8), with: AppSigningKey(), password: wrongPassword)
        }
    }

    @Test("Repeated sign calls use the same key")
    func sign_secondCallReusesKey() throws {
        defer { try? manager.removeKey(AppSigningKey()) }
        let payload = Data("hello".utf8)
        _ = try manager.sign(payload: payload, with: AppSigningKey(), password: password)
        let pub1 = try manager.getPublicKey(AppSigningKey())
        _ = try manager.sign(payload: payload, with: AppSigningKey(), password: password)
        let pub2 = try manager.getPublicKey(AppSigningKey())
        #expect(pub1 == pub2)
    }

    // MARK: - encrypt / decrypt roundtrip

    @Test("encrypt then decrypt recovers original plaintext")
    func encrypt_decrypt_roundtrip() throws {
        defer { try? manager.removeKey(AppDecryptKey()) }
        let plaintext = Data("Sensitive payload 🔑".utf8)
        _ = try manager.sign(payload: Data("x".utf8), with: AppDecryptKey(), password: password)
        let ciphertext = try manager.encrypt(data: plaintext, with: AppDecryptKey())
        let recovered = try manager.decrypt(encodedData: ciphertext, with: AppDecryptKey(), password: password)
        #expect(recovered == plaintext)
    }

    @Test("encrypt output has ECIES overhead (> 81 bytes)")
    func encrypt_producesOverhead() throws {
        defer { try? manager.removeKey(AppDecryptKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: AppDecryptKey(), password: password)
        let ciphertext = try manager.encrypt(data: Data("hello".utf8), with: AppDecryptKey())
        #expect(ciphertext.count > 81)
    }

    @Test("decrypt with wrong password throws invalidPassword")
    func decrypt_wrongPasswordThrowsInvalidPassword() throws {
        defer { try? manager.removeKey(AppDecryptKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: AppDecryptKey(), password: password)
        let ciphertext = try manager.encrypt(data: Data("secret".utf8), with: AppDecryptKey())
        #expect(throws: DecryptPasswordError.invalidPassword(name: AppDecryptKey().name)) {
            try manager.decrypt(encodedData: ciphertext, with: AppDecryptKey(), password: wrongPassword)
        }
    }

    @Test("decrypt with short payload throws invalidPayload")
    func decrypt_shortPayloadThrowsInvalidPayload() throws {
        defer { try? manager.removeKey(AppDecryptKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: AppDecryptKey(), password: password)
        #expect(throws: DecryptPasswordError.invalidPayload) {
            try manager.decrypt(encodedData: Data(repeating: 0, count: 81), with: AppDecryptKey(), password: password)
        }
    }

    // MARK: - deriveSharedSecret roundtrip

    @Test("deriveSharedSecret matches the ephemeral-side computation")
    func deriveSharedSecret_matchesEphemeralSide() throws {
        defer { try? manager.removeKey(AppDeriveKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: AppDeriveKey(), password: password)
        let ephemeralPriv = P256.KeyAgreement.PrivateKey()
        let ourSecret = try manager.deriveSharedSecret(
            with: AppDeriveKey(), publicKey: ephemeralPriv.publicKey.x963Representation, password: password
        )
        #expect(ourSecret.count == 32)
        let storedPub = try P256.KeyAgreement.PublicKey(derRepresentation: manager.getPublicKey(AppDeriveKey()))
        let theirSecret = try ephemeralPriv.sharedSecretFromKeyAgreement(with: storedPub).withUnsafeBytes { Data($0) }
        #expect(ourSecret == theirSecret)
    }

    @Test("deriveSharedSecret with wrong password throws invalidPassword")
    func deriveSharedSecret_wrongPasswordThrows() throws {
        defer { try? manager.removeKey(AppDeriveKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: AppDeriveKey(), password: password)
        #expect(throws: DerivePasswordError.invalidPassword(name: AppDeriveKey().name)) {
            try manager.deriveSharedSecret(
                with: AppDeriveKey(), publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
                password: wrongPassword
            )
        }
    }

    // MARK: - configurationMismatch

    @Test("Using same key name with different trait throws configurationMismatch")
    @BiometryActor
    func configurationMismatch_differentTrait() throws {
        defer { try? manager.removeKey(AppSigningKey()) }
        struct BiometryKey: BiometryAnyProtectedKey { let name = "integration.password.signing" }
        _ = try manager.sign(payload: Data("x".utf8), with: AppSigningKey(), password: password)
        #expect(throws: SignBiometryAnyError.configurationMismatch(name: "integration.password.signing")) {
            try manager.sign(payload: Data("x".utf8), with: BiometryKey(), laContext: nil)
        }
    }
}
