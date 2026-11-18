//
//  KeyStoreSpy.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import Foundation

@testable import KeyManagement

final class KeyStoreSpy: KeyStore, @unchecked Sendable {

    // MARK: - hasKey

    var hasKeyCallCount = 0
    var hasKeyStub = false
    var hasKeyError: KeyStoreError?
    func hasKey(named name: String) throws(KeyStoreError) -> Bool {
        hasKeyCallCount += 1
        if let error = hasKeyError { throw error }
        return hasKeyStub
    }

    // MARK: - createSigningKey

    var createCallCount = 0
    var createError: KeyStoreError?
    func createSigningKey(named name: String, trait: ProtectionTrait, protectionMode: ProtectionMode, password: Data?)
        throws(KeyStoreError) {
        createCallCount += 1
        if let error = createError { throw error }
    }

    // MARK: - getPublicKey

    var getPublicKeyStub = Data()
    var getPublicKeyError: KeyStoreError?
    func getPublicKey(named name: String) throws(KeyStoreError) -> Data {
        if let error = getPublicKeyError { throw error }
        return getPublicKeyStub
    }

    // MARK: - sign

    var signStub = Data()
    var signError: KeyStoreError?
    func sign(payload: Data, withKeyNamed keyName: String, credential: KeyCredential) throws(KeyStoreError) -> Data {
        if let error = signError { throw error }
        return signStub
    }

    // MARK: - deriveSharedSecret

    struct DeriveCall {
        let keyName: String
        let publicKey: Data
    }
    var deriveCalls: [DeriveCall] = []
    var deriveStub = Data()
    var deriveError: KeyStoreError?
    func deriveSharedSecret(withKeyNamed keyName: String, publicKey: Data, credential: KeyCredential)
        throws(KeyStoreError) -> Data {
        deriveCalls.append(DeriveCall(keyName: keyName, publicKey: publicKey))
        if let error = deriveError { throw error }
        return deriveStub
    }

    // MARK: - encrypt

    var encryptStub = Data()
    var encryptError: KeyStoreError?
    func encrypt(data: Data, keyName: String) throws(KeyStoreError) -> Data {
        if let error = encryptError { throw error }
        return encryptStub
    }

    // MARK: - decrypt

    var decryptStub = Data()
    var decryptError: KeyStoreError?
    func decrypt(encodedData: Data, credential: KeyCredential, keyName: String) throws(KeyStoreError) -> Data {
        if let error = decryptError { throw error }
        return decryptStub
    }

    // MARK: - removeSigningKey

    var removeCallCount = 0
    var removeError: KeyStoreError?
    func removeSigningKey(named name: String) throws(KeyStoreError) {
        removeCallCount += 1
        if let error = removeError { throw error }
    }

}
