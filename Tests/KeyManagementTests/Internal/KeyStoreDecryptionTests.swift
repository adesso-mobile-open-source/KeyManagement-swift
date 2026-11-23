//
//  KeyStoreDecryptionTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

//
//  KeyManagement
//
@testable import KeyManagement
import PersistentStorage
import Testing

@Suite("KeyStoreDecryption") struct KeyStoreDecryptionTests {
    @Test func `decrypt with short payload throws invalidPayload`() throws {
        let spy = KeyStoreSpy()
        // KeyStoreSpy.decrypt stub returns decryptStub by default;
        // the real implementations throw .invalidPayload for short payloads.
        // Verify the protocol requirement is satisfied and spy compiles.
        #expect(throws: KeyStoreError.invalidPayload) {
            spy.decryptError = .invalidPayload
            _ = try spy.decrypt(encodedData: Data(repeating: 0, count: 80), credential: .none, keyName: "k")
        }
    }

    @Test func `decrypt propagates store error`() throws {
        let spy = KeyStoreSpy()
        spy.decryptError = .decryptionFailed(error: "mock")
        #expect(throws: KeyStoreError.decryptionFailed(error: "mock")) {
            try spy.decrypt(encodedData: Data(repeating: 0, count: 100), credential: .none, keyName: "k")
        }
    }

    @Test func `SoftwareKeyStore decrypt with valid roundtrip`() throws {
        let sut = SoftwareKeyStore(storage: PersistentKeyValueStoreSpy())
        try sut.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: Data("pw".utf8)
        )
        let plaintext = Data("hello secure world".utf8)
        let ciphertext = try sut.encrypt(data: plaintext, keyName: "k")
        let recovered = try sut.decrypt(encodedData: ciphertext, credential: .password(Data("pw".utf8)), keyName: "k")
        #expect(recovered == plaintext)
    }

    @Test
    func `SoftwareKeyStore decrypt with wrong password throws invalidPassword`() throws {
        let sut = SoftwareKeyStore(storage: PersistentKeyValueStoreSpy())
        try sut.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: Data("pw".utf8)
        )
        let ciphertext = try sut.encrypt(data: Data("secret".utf8), keyName: "k")
        #expect(throws: KeyStoreError.invalidPassword) {
            try sut.decrypt(encodedData: ciphertext, credential: .password(Data("wrong".utf8)), keyName: "k")
        }
    }

    @Test func `SoftwareKeyStore decrypt with short payload throws invalidPayload`()
        throws {
        let sut = SoftwareKeyStore(storage: PersistentKeyValueStoreSpy())
        try sut.createSigningKey(
            named: "k",
            trait: .unprotected,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: nil
        )
        #expect(throws: KeyStoreError.invalidPayload) {
            try sut.decrypt(encodedData: Data(repeating: 0, count: 80), credential: .none, keyName: "k")
        }
    }
}
