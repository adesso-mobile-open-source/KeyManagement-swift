//
//  KeyManager+UserPresence.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import LocalAuthentication

public extension KeyManagerImpl {
    @KeyManagementActor func create(key: some UserPresenceProtectedKey) throws(CreateKeyError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .userPresence) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) == true { throw .keyAlreadyExists(name: key.name) }
        do {
            try autoCreate(named: key.name, trait: .userPresence, protectionMode: key.protectionMode, password: nil)
            return try keyStore.getPublicKey(named: key.name)
        } catch { throw .creationFailed(name: key.name, error: error.localizedDescription) }
    }

    func encrypt(data: Data, with key: some UserPresenceProtectedKey) throws(EncryptError) -> Data {
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .userPresence, protectionMode: key.protectionMode, password: nil)
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

    @KeyManagementActor func sign(
        payload: Data,
        with key: some UserPresenceProtectedKey,
        laContext: LAContext? = nil
    ) throws(SignUserPresenceError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .userPresence) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .userPresence, protectionMode: key.protectionMode, password: nil)
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do {
            return try keyStore.sign(payload: payload, withKeyNamed: key.name, credential: .laContext(laContext))
        } catch let caughtError where caughtError.isUserCancelled {
            throw .userCancelled(name: key.name)
        } catch let caughtError where caughtError.isBiometryLockout {
            throw .biometryLockout(name: key.name)
        } catch {
            throw .signingFailed(name: key.name, error: error.localizedDescription)
        }
    }

    @KeyManagementActor func deriveSharedSecret(
        with key: some UserPresenceProtectedKey,
        publicKey: Data,
        laContext: LAContext? = nil
    ) throws(DeriveUserPresenceError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .userPresence) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .userPresence, protectionMode: key.protectionMode, password: nil)
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do {
            return try keyStore.deriveSharedSecret(
                withKeyNamed: key.name,
                publicKey: publicKey,
                credential: .laContext(laContext)
            )
        } catch let caughtError where caughtError.isUserCancelled {
            throw .userCancelled(name: key.name)
        } catch let caughtError where caughtError.isBiometryLockout {
            throw .biometryLockout(name: key.name)
        } catch {
            throw .derivationFailed(name: key.name, error: error.localizedDescription)
        }
    }

    @KeyManagementActor func decrypt(
        encodedData: Data,
        with key: some UserPresenceProtectedKey,
        laContext: LAContext? = nil
    ) throws(DecryptUserPresenceError) -> Data {
        guard encodedData.count > 81 else { throw .invalidPayload }

        if case .mismatch = validateConfiguration(for: key, trait: .userPresence) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(named: key.name, trait: .userPresence, protectionMode: key.protectionMode, password: nil)
            } catch { throw .keyCreationFailed(error: error.localizedDescription) }
        }
        do {
            return try keyStore.decrypt(encodedData: encodedData, credential: .laContext(laContext), keyName: key.name)
        } catch let caughtError where caughtError.isUserCancelled {
            throw .userCancelled(name: key.name)
        } catch let caughtError where caughtError.isBiometryLockout {
            throw .biometryLockout(name: key.name)
        } catch let caughtError where caughtError.isInvalidPayload {
            throw .invalidPayload
        } catch {
            throw .decryptionFailed(name: key.name, error: error.localizedDescription)
        }
    }
}
