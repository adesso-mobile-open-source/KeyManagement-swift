//
//  UnprotectedKeyIntegrationTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

// UnprotectedKey integration tests.
//
// Protection: privateKeyUsage only (no access control flags)
// Auth: NONE — no user interaction required
// Device: real Secure Enclave — key lives in hardware, proves device possession
// Human interaction: NONE
//

import CryptoKit
import Foundation
import KeyManagement
import Testing

@Suite("UnprotectedKey — Integration")
struct UnprotectedKeyIntegrationTests {
    struct DeviceSigningKey: UnprotectedKey { let name = "integration.unprotected.signing" }
    struct DeviceDecryptKey: UnprotectedKey { let name = "integration.unprotected.decrypt" }
    struct DeviceDeriveKey: UnprotectedKey { let name = "integration.unprotected.derive" }

    let manager = KeyManagerImpl(applicationTag: integrationAppTag)

    init() {
        try? manager.removeKey(DeviceSigningKey())
        try? manager.removeKey(DeviceDecryptKey())
        try? manager.removeKey(DeviceDeriveKey())
    }

    // MARK: - hasKey / removeKey

    @Test
    func `hasKey returns false before first write`() throws {
        defer { try? manager.removeKey(DeviceSigningKey()) }
        #expect(try manager.hasKey(DeviceSigningKey()) == false)
    }

    @Test
    func `hasKey returns true after auto-create via sign`() throws {
        defer { try? manager.removeKey(DeviceSigningKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: DeviceSigningKey())
        #expect(try manager.hasKey(DeviceSigningKey()) == true)
    }

    @Test
    func `removeKey clears the key`() throws {
        _ = try manager.sign(payload: Data("x".utf8), with: DeviceSigningKey())
        try manager.removeKey(DeviceSigningKey())
        #expect(try manager.hasKey(DeviceSigningKey()) == false)
    }

    // MARK: - getPublicKey

    @Test
    func `getPublicKey throws keyNotFound before first write`() throws {
        defer { try? manager.removeKey(DeviceSigningKey()) }
        #expect(throws: GetPublicKeyError.keyNotFound(name: DeviceSigningKey().name)) {
            try manager.getPublicKey(DeviceSigningKey())
        }
    }

    @Test
    func `getPublicKey returns 91-byte DER-encoded P-256 key`() throws {
        defer { try? manager.removeKey(DeviceSigningKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: DeviceSigningKey())
        let pub = try manager.getPublicKey(DeviceSigningKey())
        #expect(pub.first == 0x30)
        #expect(pub.count == 91)
    }

    // MARK: - sign roundtrip

    @Test
    func `sign produces a verifiable ECDSA signature`() throws {
        defer { try? manager.removeKey(DeviceSigningKey()) }
        let payload = Data("Device identity payload".utf8)
        let signature = try manager.sign(payload: payload, with: DeviceSigningKey())
        let publicKey = try P256.Signing.PublicKey(derRepresentation: manager.getPublicKey(DeviceSigningKey()))
        let ecdsaSignature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        #expect(publicKey.isValidSignature(ecdsaSignature, for: payload))
    }

    @Test
    func `Different payloads produce different signatures`() throws {
        defer { try? manager.removeKey(DeviceSigningKey()) }
        let sig1 = try manager.sign(payload: Data("payload1".utf8), with: DeviceSigningKey())
        let sig2 = try manager.sign(payload: Data("payload2".utf8), with: DeviceSigningKey())
        #expect(sig1 != sig2)
    }

    @Test
    func `Repeated sign calls reuse the same key`() throws {
        defer { try? manager.removeKey(DeviceSigningKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: DeviceSigningKey())
        let pub1 = try manager.getPublicKey(DeviceSigningKey())
        _ = try manager.sign(payload: Data("y".utf8), with: DeviceSigningKey())
        let pub2 = try manager.getPublicKey(DeviceSigningKey())
        #expect(pub1 == pub2)
    }

    // MARK: - encrypt / decrypt roundtrip

    @Test
    func `encrypt then decrypt recovers original plaintext`() throws {
        defer { try? manager.removeKey(DeviceDecryptKey()) }
        let plaintext = Data("Device-bound secret — no auth needed 🔑".utf8)
        _ = try manager.sign(payload: Data("x".utf8), with: DeviceDecryptKey())
        let ciphertext = try manager.encrypt(data: plaintext, with: DeviceDecryptKey())
        let recovered = try manager.decrypt(encodedData: ciphertext, with: DeviceDecryptKey())
        #expect(recovered == plaintext)
    }

    @Test
    func `encrypt output has ECIES overhead (> 81 bytes)`() throws {
        defer { try? manager.removeKey(DeviceDecryptKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: DeviceDecryptKey())
        let ciphertext = try manager.encrypt(data: Data("hello".utf8), with: DeviceDecryptKey())
        #expect(ciphertext.count > 81)
    }

    @Test
    func `decrypt with short payload throws invalidPayload`() throws {
        defer { try? manager.removeKey(DeviceDecryptKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: DeviceDecryptKey())
        #expect(throws: DecryptUnprotectedError.invalidPayload) {
            try manager.decrypt(encodedData: Data(repeating: 0, count: 81), with: DeviceDecryptKey())
        }
    }

    @Test
    func `encrypt autocreates key when key has not been created`() throws {
        defer { try? manager.removeKey(DeviceDecryptKey()) }
        _ = try manager.encrypt(data: Data("x".utf8), with: DeviceDecryptKey())
        #expect(try manager.hasKey(DeviceDecryptKey()))
    }

    // MARK: - deriveSharedSecret roundtrip

    @Test
    func `deriveSharedSecret matches the ephemeral-side computation`() throws {
        defer { try? manager.removeKey(DeviceDeriveKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: DeviceDeriveKey())
        let ephemeralPriv = P256.KeyAgreement.PrivateKey()
        let ourSecret = try manager.deriveSharedSecret(
            with: DeviceDeriveKey(), publicKey: ephemeralPriv.publicKey.x963Representation
        )
        #expect(ourSecret.count == 32)
        let storedPub = try P256.KeyAgreement.PublicKey(derRepresentation: manager.getPublicKey(DeviceDeriveKey()))
        let theirSecret = try ephemeralPriv.sharedSecretFromKeyAgreement(with: storedPub).withUnsafeBytes { Data($0) }
        #expect(ourSecret == theirSecret)
    }

    @Test
    func `deriveSharedSecret with invalid ephemeral key throws`() throws {
        defer { try? manager.removeKey(DeviceDeriveKey()) }
        _ = try manager.sign(payload: Data("x".utf8), with: DeviceDeriveKey())
        #expect(throws: DeriveUnprotectedError.self) {
            try manager.deriveSharedSecret(with: DeviceDeriveKey(), publicKey: Data(repeating: 0xFF, count: 10))
        }
    }
}
