//
//  KeyManager+PasswordProtected.swift
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
    func sign(payload: Data, with key: some PasswordProtectedKey, password: Data) throws(SignPasswordError)
        -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .password) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(
                    named: key.name,
                    trait: .password,
                    protectionMode: key.protectionMode,
                    password: password
                )
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do {
            return try keyStore.sign(payload: payload, withKeyNamed: key.name, credential: .password(password))
        } catch let caughtError where caughtError.isInvalidPassword {
            throw .invalidPassword(name: key.name)
        } catch {
            throw .signingFailed(name: key.name, error: error.localizedDescription)
        }
    }

    func deriveSharedSecret(with key: some PasswordProtectedKey, publicKey: Data, password: Data)
        throws(DerivePasswordError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .password) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(
                    named: key.name,
                    trait: .password,
                    protectionMode: key.protectionMode,
                    password: password
                )
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do {
            return try keyStore.deriveSharedSecret(
                withKeyNamed: key.name,
                publicKey: publicKey,
                credential: .password(password)
            )
        } catch let caughtError where caughtError.isInvalidPassword {
            throw .invalidPassword(name: key.name)
        } catch {
            throw .derivationFailed(name: key.name, error: error.localizedDescription)
        }
    }

    func encrypt(data: Data, with key: some PasswordProtectedKey) throws(EncryptError) -> Data {
        guard (try? keyStore.hasKey(named: key.name)) == true else {
            throw .keyNotFound(name: key.name)
        }

        do {
            return try keyStore.encrypt(data: data, keyName: key.name)
        } catch {
            throw .encryptionFailed(name: key.name, error: error.localizedDescription)
        }
    }

    func encrypt(data: Data, with key: some PasswordProtectedKey, generateKeyWithPassword password: Data)
        throws(EncryptError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .password) {
            throw .keyCreationFailed(error: "Configuration mismatch for key '\(key.name)'")
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(
                    named: key.name,
                    trait: .password,
                    protectionMode: key.protectionMode,
                    password: password
                )
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do { return try keyStore.encrypt(data: data, keyName: key.name) } catch {
            throw .encryptionFailed(name: key.name, error: error.localizedDescription)
        }
    }

    func create(key: some PasswordProtectedKey, password: Data) throws(CreateKeyError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .password) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) == true { throw .keyAlreadyExists(name: key.name) }
        do {
            try autoCreate(named: key.name, trait: .password, protectionMode: key.protectionMode, password: password)
            return try keyStore.getPublicKey(named: key.name)
        } catch { throw .creationFailed(name: key.name, error: error.localizedDescription) }
    }

    func decrypt(encodedData: Data, with key: some PasswordProtectedKey, password: Data)
        throws(DecryptPasswordError) -> Data {
        guard encodedData.count > 81 else { throw .invalidPayload }

        if case .mismatch = validateConfiguration(for: key, trait: .password) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(
                    named: key.name,
                    trait: .password,
                    protectionMode: key.protectionMode,
                    password: password
                )
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do {
            return try keyStore.decrypt(encodedData: encodedData, credential: .password(password), keyName: key.name)
        } catch let caughtError where caughtError.isInvalidPassword {
            throw .invalidPassword(name: key.name)
        } catch let caughtError where caughtError.isInvalidPayload {
            throw .invalidPayload
        } catch {
            throw .decryptionFailed(name: key.name, error: error.localizedDescription)
        }
    }
}
