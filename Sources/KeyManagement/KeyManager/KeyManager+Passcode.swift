//
//  KeyManager+Passcode.swift
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

extension KeyManagerImpl {

    @KeyManagementActor public func create<K: PasscodeProtectedKey>(key: K) throws(CreateKeyError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .passcode) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) == true { throw .keyAlreadyExists(name: key.name) }
        do {
            try autoCreate(named: key.name, trait: .passcode, protectionMode: key.protectionMode, password: nil)
            return try keyStore.getPublicKey(named: key.name)
        } catch { throw .creationFailed(name: key.name, error: error.localizedDescription) }
    }

    public func encrypt<K: PasscodeProtectedKey>(data: Data, with key: K) throws(EncryptError) -> Data {
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .passcode, protectionMode: key.protectionMode, password: nil)
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

    @KeyManagementActor public func sign<K: PasscodeProtectedKey>(
        payload: Data,
        with key: K
    ) throws(SignPasscodeError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .passcode) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .passcode, protectionMode: key.protectionMode, password: nil)
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do { return try keyStore.sign(payload: payload, withKeyNamed: key.name, credential: .none) } catch {
            throw .signingFailed(name: key.name, error: error.localizedDescription)
        }
    }

    @KeyManagementActor public func deriveSharedSecret<K: PasscodeProtectedKey>(
        with key: K,
        publicKey: Data
    ) throws(DerivePasscodeError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .passcode) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .passcode, protectionMode: key.protectionMode, password: nil)
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do {
            return try keyStore.deriveSharedSecret(withKeyNamed: key.name, publicKey: publicKey, credential: .none)
        } catch { throw .derivationFailed(name: key.name, error: error.localizedDescription) }
    }

    @KeyManagementActor public func decrypt<K: PasscodeProtectedKey>(
        encodedData: Data,
        with key: K
    ) throws(DecryptPasscodeError) -> Data {
        guard encodedData.count > 81 else { throw .invalidPayload }
        if case .mismatch = validateConfiguration(for: key, trait: .passcode) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .passcode, protectionMode: key.protectionMode, password: nil)
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
