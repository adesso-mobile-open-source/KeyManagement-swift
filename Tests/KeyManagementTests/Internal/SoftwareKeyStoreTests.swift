//
//  SoftwareKeyStoreTests.swift
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
import CryptoKit
import PersistentStorage
import Testing

@testable import KeyManagement

// Helper key descriptors used across software store tests
private struct SWPasswordKey: PasswordProtectedKey { let name: String }
private struct SWUnprotectedKey: UnprotectedKey { let name: String }

@Suite("SoftwareKeyStore") struct SoftwareKeyStoreTests {

    private func makeSUT() -> (SoftwareKeyStore, PersistentKeyValueStoreSpy) {
        let spy = PersistentKeyValueStoreSpy()
        return (SoftwareKeyStore(storage: spy), spy)
    }

    @Test("hasKey returns false when key absent") func hasKey_absent() throws {
        let (sut, _) = makeSUT()
        #expect(try sut.hasKey(named: "missing") == false)
    }

    @Test("createSigningKey then hasKey returns true") func createSigningKey_thenHasKey() throws {
        let (sut, _) = makeSUT()
        try sut.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: Data("pw".utf8)
        )
        #expect(try sut.hasKey(named: "k") == true)
    }

    @Test("getPublicKey returns 91-byte DER key") func getPublicKey_returns91Bytes() throws {
        let (sut, _) = makeSUT()
        try sut.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: Data("pw".utf8)
        )
        let pub = try sut.getPublicKey(named: "k")
        #expect(pub.starts(with: [0x30]))
        #expect(pub.count == 91)
    }

    @Test("getPublicKey throws when key absent") func getPublicKey_absent() throws {
        let (sut, _) = makeSUT()
        #expect(throws: KeyStoreError.self) { try sut.getPublicKey(named: "missing") }
    }

    @Test("sign with correct password returns DER signature") func sign_correctPassword() throws {
        let (sut, _) = makeSUT()
        let pwd = Data("pw".utf8)
        try sut.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: pwd
        )
        let sig = try sut.sign(payload: Data("hello".utf8), withKeyNamed: "k", credential: .password(pwd))
        #expect(sig.starts(with: [0x30]))
    }

    @Test("sign with wrong password throws cannotSignDataInvalidPassword") func sign_wrongPassword() throws {
        let (sut, _) = makeSUT()
        try sut.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: Data("pw".utf8)
        )
        #expect(throws: KeyStoreError.cannotSignDataInvalidPassword(name: "k")) {
            try sut.sign(payload: Data("hello".utf8), withKeyNamed: "k", credential: .password(Data("wrong".utf8)))
        }
    }

    @Test("sign with .none credential always succeeds for unprotected key") func sign_noneCredential() throws {
        let (sut, _) = makeSUT()
        try sut.createSigningKey(
            named: "k",
            trait: .unprotected,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: nil
        )
        let sig = try sut.sign(payload: Data("hello".utf8), withKeyNamed: "k", credential: .none)
        #expect(sig.starts(with: [0x30]))
    }

    @Test("removeSigningKey removes key") func removeSigningKey() throws {
        let (sut, _) = makeSUT()
        try sut.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: Data("pw".utf8)
        )
        try sut.removeSigningKey(named: "k")
        #expect(try sut.hasKey(named: "k") == false)
    }

    @Test("injectKey for PasswordProtectedKey then hasKey returns true") func injectKey_password() throws {
        let (sut, _) = makeSUT()
        let key = SWPasswordKey(name: "imported")
        try sut.injectKey(key, password: Data("pw".utf8), privateKeyDER: P256.Signing.PrivateKey().derRepresentation)
        #expect(try sut.hasKey(named: "imported") == true)
    }

    @Test("injectKey for UnprotectedKey then hasKey returns true") func injectKey_unprotected() throws {
        let (sut, _) = makeSUT()
        let key = SWUnprotectedKey(name: "bare")
        try sut.injectKey(key, privateKeyDER: P256.Signing.PrivateKey().derRepresentation)
        #expect(try sut.hasKey(named: "bare") == true)
    }

    @Test("init loads persisted keys from storage") func init_loadsFromStorage() throws {
        let spy = PersistentKeyValueStoreSpy()
        let first = SoftwareKeyStore(storage: spy)
        try first.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: Data("pw".utf8)
        )
        let second = SoftwareKeyStore(storage: spy)
        #expect(try second.hasKey(named: "k") == true)
    }

    @Test("init with corrupted storage loads empty set") func init_corruptedStorage() throws {
        let spy = PersistentKeyValueStoreSpy()
        try spy.set(data: Data("garbage".utf8), for: "adesso_signing_keys")
        let sut = SoftwareKeyStore(storage: spy)
        #expect(try sut.hasKey(named: "anything") == false)
    }

    @Test("deriveSharedSecret returns 32-byte shared secret") func deriveSharedSecret() throws {
        let (sut, _) = makeSUT()
        let pwd = Data("secret".utf8)
        try sut.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: pwd
        )
        let ephemeralPriv = P256.KeyAgreement.PrivateKey()
        let secret = try sut.deriveSharedSecret(
            withKeyNamed: "k",
            publicKey: ephemeralPriv.publicKey.x963Representation,
            credential: .password(pwd)
        )
        #expect(secret.count == 32)
    }

    @Test("deriveSharedSecret with wrong password throws invalidPassword") func deriveSharedSecret_wrongPassword()
        throws {
        let (sut, _) = makeSUT()
        try sut.createSigningKey(
            named: "k",
            trait: .password,
            protectionMode: .whenUnlockedThisDeviceOnly,
            password: Data("correct".utf8)
        )
        #expect(throws: KeyStoreError.self) {
            try sut.deriveSharedSecret(
                withKeyNamed: "k",
                publicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
                credential: .password(Data("wrong".utf8))
            )
        }
    }
}
