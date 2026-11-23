//
//  KeyManager+Unprotected.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import Foundation

public extension KeyManagerImpl {
    func create(key: some UnprotectedKey) throws(CreateKeyError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .unprotected) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) == true { throw .keyAlreadyExists(name: key.name) }
        do {
            try autoCreate(named: key.name, trait: .unprotected, protectionMode: key.protectionMode, password: nil)
            return try keyStore.getPublicKey(named: key.name)
        } catch { throw .creationFailed(name: key.name, error: error.localizedDescription) }
    }

    func encrypt(data: Data, with key: some UnprotectedKey) throws(EncryptError) -> Data {
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .unprotected, protectionMode: key.protectionMode, password: nil)
            } catch {
                throw EncryptError.keyCreationFailed(error: error.localizedDescription)
            }
        }
        do {
            return try keyStore.encrypt(data: data, keyName: key.name)
        } catch {
            throw EncryptError.encryptionFailed(name: key.name, error: error.localizedDescription)
        }
    }

    func sign(payload: Data, with key: some UnprotectedKey) throws(SignUnprotectedError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .unprotected) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .unprotected, protectionMode: key.protectionMode, password: nil)
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do { return try keyStore.sign(payload: payload, withKeyNamed: key.name, credential: .none) } catch {
            throw .signingFailed(name: key.name, error: error.localizedDescription)
        }
    }

    func deriveSharedSecret(with key: some UnprotectedKey, publicKey: Data) throws(DeriveUnprotectedError)
        -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .unprotected) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .unprotected, protectionMode: key.protectionMode, password: nil)
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do {
            return try keyStore.deriveSharedSecret(withKeyNamed: key.name, publicKey: publicKey, credential: .none)
        } catch { throw .derivationFailed(name: key.name, error: error.localizedDescription) }
    }

    func decrypt(encodedData: Data, with key: some UnprotectedKey) throws(DecryptUnprotectedError) -> Data {
        guard encodedData.count > 81 else { throw .invalidPayload }

        if case .mismatch = validateConfiguration(for: key, trait: .unprotected) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .unprotected, protectionMode: key.protectionMode, password: nil)
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do {
            return try keyStore.decrypt(encodedData: encodedData, credential: .none, keyName: key.name)
        } catch let caughtError where caughtError.isInvalidPayload {
            throw .invalidPayload
        } catch {
            throw .decryptionFailed(name: key.name, error: error.localizedDescription)
        }
    }
}
