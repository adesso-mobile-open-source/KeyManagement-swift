//
//  KeyManagerImpl.swift
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
import LocalAuthentication
import Security

/// The production implementation of the ``KeyManager`` protocol.
///
/// `KeyManagerImpl` is the concrete class you instantiate in your application.
/// On a real device it is backed by the Secure Enclave via `SecureEnclaveKeyStore`.
/// On the simulator it falls back to `SoftwareKeyStore`, which supports
/// ``PasswordProtectedKey`` and ``UnprotectedKey`` traits only.
///
/// ## Creating an instance
///
/// ```swift
/// let manager = KeyManagerImpl(applicationTag: "com.example.app")
/// ```
///
/// Create one instance per `applicationTag` and keep it alive for the lifetime
/// of the feature — repeated instantiation is safe but unnecessary.
///
/// ## Testability
///
/// Declare your dependencies as `any KeyManager` and inject `KeyManagerImpl`
/// at the composition root. In tests, substitute a hand-written spy that
/// conforms to `KeyManager`.
public final class KeyManagerImpl: KeyManager, Sendable {
    let keyStore: any KeyStore
    let configStore: KeyConfigurationStore
    let enrollmentMonitor: any KeyEnrollmentStateMonitor
    let applicationTag: String

    /// Creates a `KeyManagerImpl` backed by the Secure Enclave on a real device,
    /// or `SoftwareKeyStore` on the simulator.
    ///
    /// - Parameter applicationTag: A reverse-DNS string that namespaces all keys
    ///   managed by this instance (e.g. `"com.example.app"`). The tag is
    ///   combined with each key's `name` to form the keychain application tag:
    ///   `"\(applicationTag).\(key.name)"`. Use the same value each time you
    ///   create a `KeyManagerImpl` — changing it makes existing keys invisible.
    public convenience init(applicationTag: String) {
        #if targetEnvironment(simulator)
            self.init(applicationTag: applicationTag, keyStore: SoftwareKeyStore())
        #else
            self.init(applicationTag: applicationTag, keyStore: SecureEnclaveKeyStore(applicationTag: applicationTag))
        #endif
    }

    /// Injection init for tests — accepts any internal KeyStore.
    init(applicationTag: String, keyStore: any KeyStore) {
        self.applicationTag = applicationTag
        self.keyStore = keyStore
        self.configStore = KeyConfigurationStore(applicationTag: applicationTag)
        self.enrollmentMonitor = KeyEnrollmentStateMonitorImpl(applicationTag: applicationTag)
    }

    /// Fully injectable init for testing all internal dependencies.
    init(
        applicationTag: String,
        keyStore: any KeyStore,
        configStore: KeyConfigurationStore,
        enrollmentMonitor: any KeyEnrollmentStateMonitor
    ) {
        self.applicationTag = applicationTag
        self.keyStore = keyStore
        self.configStore = configStore
        self.enrollmentMonitor = enrollmentMonitor
    }
}

// MARK: - Read-only methods

extension KeyManagerImpl {

    public func hasKey<K: KeyDescriptor>(_ key: K) throws(HasKeyError) -> Bool {
        do { return try keyStore.hasKey(named: key.name) } catch {
            throw .lookupFailed(name: key.name, error: error.localizedDescription)
        }
    }

    public func getPublicKey<K: KeyDescriptor>(_ key: K) throws(GetPublicKeyError) -> Data {
        do {
            guard try keyStore.hasKey(named: key.name) else { throw GetPublicKeyError.keyNotFound(name: key.name) }
            return try keyStore.getPublicKey(named: key.name)
        } catch let caughtError as GetPublicKeyError {
            throw caughtError
        } catch {
            throw .retrievalFailed(name: key.name, error: error.localizedDescription)
        }
    }

    public func removeKey<K: KeyDescriptor>(_ key: K) throws(RemoveKeyError) {
        do { try keyStore.removeSigningKey(named: key.name) } catch {
            throw .removalFailed(name: key.name, status: error.osstatus ?? errSecInternalError)
        }
        configStore.remove(forKeyNamed: key.name)
    }

    public func removeKey<K: BiometryCurrentSetProtectedKey>(_ key: K) throws(RemoveKeyError) {
        do { try keyStore.removeSigningKey(named: key.name) } catch {
            throw .removalFailed(name: key.name, status: error.osstatus ?? errSecInternalError)
        }
        configStore.remove(forKeyNamed: key.name)
        enrollmentMonitor.clearEnrollmentState(forKeyNamed: key.name)
    }

    public func hasBiometricEnrollmentChanged<K: BiometryCurrentSetProtectedKey>(for key: K)
        throws(EnrollmentCheckError) -> Bool { try enrollmentMonitor.hasEnrollmentChanged(forKeyNamed: key.name) }
}

// MARK: - Internal helpers

extension KeyManagerImpl {

    func validateConfiguration<K: KeyDescriptor>(for key: K, trait: ProtectionTrait) -> ConfigValidation {
        if let existing = configStore.record(forKeyNamed: key.name) {
            guard existing.trait == trait, existing.protectionMode == key.protectionMode else { return .mismatch }
            return .valid
        }
        configStore.store(
            KeyConfigurationRecord(trait: trait, protectionMode: key.protectionMode),
            forKeyNamed: key.name
        )
        return .valid
    }

    func autoCreate(named name: String, trait: ProtectionTrait, protectionMode: ProtectionMode, password: Data?)
        throws(KeyStoreError) {
        try keyStore.createSigningKey(
            named: name,
            trait: trait,
            protectionMode: protectionMode,
            password: password
        )
    }
}

enum ConfigValidation { case valid, mismatch }
