//
//  KeyManager+BiometryCurrentSet.swift
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
    @KeyManagementActor func create(key: some BiometryCurrentSetProtectedKey) throws(CreateKeyError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .biometryCurrentSet) {
            throw .configurationMismatch(name: key.name)
        }
        if (try? keyStore.hasKey(named: key.name)) == true { throw .keyAlreadyExists(name: key.name) }
        do {
            try autoCreate(
                named: key.name,
                trait: .biometryCurrentSet,
                protectionMode: key.protectionMode,
                password: nil
            )
            enrollmentMonitor.storeEnrollmentState(forKeyNamed: key.name)
            return try keyStore.getPublicKey(named: key.name)
        } catch { throw .creationFailed(name: key.name, error: error.localizedDescription) }
    }

    func encrypt(data: Data, with key: some BiometryCurrentSetProtectedKey) throws(EncryptError) -> Data {
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(
                    named: key.name,
                    trait: .biometryCurrentSet,
                    protectionMode: key.protectionMode,
                    password: nil
                )
                enrollmentMonitor.storeEnrollmentState(forKeyNamed: key.name)
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
        with key: some BiometryCurrentSetProtectedKey,
        laContext: LAContext? = nil
    ) throws(SignBiometryCurrentSetError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .biometryCurrentSet) {
            throw .configurationMismatch(name: key.name)
        }
        try ensureKeyAndEnrollment(
            for: key,
            keyCreationFailed: { SignBiometryCurrentSetError.keyCreationFailed(error: $0) },
            enrollmentChanged: { SignBiometryCurrentSetError.enrollmentChanged(name: $0) },
            operationFailed: { SignBiometryCurrentSetError.signingFailed(name: $0, error: $1) }
        )
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
        with key: some BiometryCurrentSetProtectedKey,
        publicKey: Data,
        laContext: LAContext? = nil
    ) throws(DeriveBiometryCurrentSetError) -> Data {
        if case .mismatch = validateConfiguration(for: key, trait: .biometryCurrentSet) {
            throw .configurationMismatch(name: key.name)
        }
        try ensureKeyAndEnrollment(
            for: key,
            keyCreationFailed: { DeriveBiometryCurrentSetError.keyCreationFailed(error: $0) },
            enrollmentChanged: { DeriveBiometryCurrentSetError.enrollmentChanged(name: $0) },
            operationFailed: { DeriveBiometryCurrentSetError.derivationFailed(name: $0, error: $1) }
        )
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
        with key: some BiometryCurrentSetProtectedKey,
        laContext: LAContext? = nil
    ) throws(DecryptBiometryCurrentSetError) -> Data {
        guard encodedData.count > 81 else { throw .invalidPayload }

        if case .mismatch = validateConfiguration(for: key, trait: .biometryCurrentSet) {
            throw .configurationMismatch(name: key.name)
        }
        try ensureKeyAndEnrollment(
            for: key,
            keyCreationFailed: { DecryptBiometryCurrentSetError.keyCreationFailed(error: $0) },
            enrollmentChanged: { DecryptBiometryCurrentSetError.enrollmentChanged(name: $0) },
            operationFailed: { DecryptBiometryCurrentSetError.decryptionFailed(name: $0, error: $1) }
        )
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

    /// Auto-creates the key if missing and verifies the biometric enrollment
    /// baseline has not changed, mapping any failure to the operation's error type.
    @KeyManagementActor private func ensureKeyAndEnrollment<E: Error>(
        for key: some BiometryCurrentSetProtectedKey,
        keyCreationFailed: (String) -> E,
        enrollmentChanged: (String) -> E,
        operationFailed: (String, String) -> E
    ) throws(E) {
        if (try? keyStore.hasKey(named: key.name)) != true {
            do {
                try autoCreate(
                    named: key.name,
                    trait: .biometryCurrentSet,
                    protectionMode: key.protectionMode,
                    password: nil
                )
                enrollmentMonitor.storeEnrollmentState(forKeyNamed: key.name)
            } catch {
                throw keyCreationFailed(error.localizedDescription)
            }
        }
        do {
            if try enrollmentMonitor.hasEnrollmentChanged(forKeyNamed: key.name) {
                throw enrollmentChanged(key.name)
            }
        } catch let caughtError as E {
            throw caughtError
        } catch {
            throw operationFailed(key.name, error.localizedDescription)
        }
    }
}
