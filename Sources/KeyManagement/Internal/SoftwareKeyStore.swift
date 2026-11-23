//
//  SoftwareKeyStore.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 22.08.25 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

#if targetEnvironment(simulator) || (os(macOS) && DEBUG)

import CryptoKit
import Foundation
import PersistentStorage

private let signingKeysPersistentStorageKey = "adesso_signing_keys"

/// An insecure, in-process software implementation of a key store.
/// For testing and development only. MUST NOT be used in production.
final class SoftwareKeyStore: KeyStore, CanInjectKey, Sendable {
    fileprivate struct KeyWrapper: Codable, Sendable {
        let password: Data
        let privateKey: P256.Signing.PrivateKey
        let trait: ProtectionTrait
        let protectionMode: ProtectionMode
    }

    // MARK: - State

    /// `NSLock` is `Sendable` and available on all iOS versions.
    /// All access to `_signingKeys` must go through `withKeys`.
    private let lock = NSLock()
    private nonisolated(unsafe) var _signingKeys: [String: KeyWrapper]

    /// Executes `body` with exclusive access to the signing-key dictionary.
    private func withKeys<T>(_ body: (inout [String: KeyWrapper]) throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body(&_signingKeys)
    }

    // MARK: - Dependencies

    private let storage: PersistentKeyValueStore

    convenience init() {
        self.init(storage: PersistentKeyValueStoreImpl(dataStore: .keychain(service: "de.adesso.softwarekeystore")))
    }

    init(storage: PersistentKeyValueStore) {
        self.storage = storage
        _signingKeys = Self.loadSigningKeysFromStorage(storage)
    }

    // MARK: - CanInjectKey

    func injectKey(_ key: some PasswordProtectedKey, password: Data, privateKeyDER: Data) throws {
        let privateKey = try P256.Signing.PrivateKey(derRepresentation: privateKeyDER)
        withKeys {
            $0[key.name] = KeyWrapper(
                password: password,
                privateKey: privateKey,
                trait: .password,
                protectionMode: key.protectionMode
            )
        }
        saveSigningKeysToStorage()
    }

    func injectKey(_ key: some UnprotectedKey, privateKeyDER: Data) throws {
        let privateKey = try P256.Signing.PrivateKey(derRepresentation: privateKeyDER)
        withKeys {
            $0[key.name] = KeyWrapper(
                password: Data(),
                privateKey: privateKey,
                trait: .unprotected,
                protectionMode: key.protectionMode
            )
        }
        saveSigningKeysToStorage()
    }

    // MARK: - KeyStore

    func hasKey(named name: String) throws(KeyStoreError) -> Bool { withKeys { $0.keys.contains(name) } }

    func createSigningKey(
        named name: String,
        trait: ProtectionTrait,
        protectionMode: ProtectionMode,
        password: Data?
    ) throws(KeyStoreError) {
        withKeys {
            $0[name] = KeyWrapper(
                password: password ?? Data(),
                privateKey: .init(),
                trait: trait,
                protectionMode: protectionMode
            )
        }
        saveSigningKeysToStorage()
    }

    func getPublicKey(named name: String) throws(KeyStoreError) -> Data {
        let wrapper = withKeys { $0[name] }
        guard let wrapper else { throw .cannotGetPublicKey(name: name, error: "Key does not exist.") }

        return wrapper.privateKey.publicKey.derRepresentation
    }

    func sign(payload: Data, withKeyNamed keyName: String, credential: KeyCredential)
        throws(KeyStoreError) -> Data {
        guard let wrapper = withKeys({ $0[keyName] }) else {
            throw .cannotGetPublicKey(name: keyName, error: "Key does not exist.")
        }

        if case let .password(pwd) = credential, pwd != wrapper.password {
            throw .cannotSignDataInvalidPassword(name: keyName)
        }

        do {
            return try wrapper.privateKey.signature(for: payload).derRepresentation
        } catch { throw .cannotSignData(name: keyName, error: "\(error)") }
    }

    func deriveSharedSecret(withKeyNamed keyName: String, publicKey: Data, credential: KeyCredential)
        throws(KeyStoreError) -> Data {
        guard let wrapper = withKeys({ $0[keyName] }) else {
            throw .cannotDeriveSharedSecret(name: keyName, error: "Key not found.")
        }

        if case let .password(pwd) = credential, pwd != wrapper.password { throw .invalidPassword }

        let rawKeyBytes = wrapper.privateKey.rawRepresentation
        guard let agreementPrivateKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: rawKeyBytes) else {
            throw .cannotDeriveSharedSecret(name: keyName, error: "Failed to convert stored key to agreement key.")
        }
        guard let ephemeralPublicKey = try? P256.KeyAgreement.PublicKey(x963Representation: publicKey) else {
            throw .cannotDeriveSharedSecret(name: keyName, error: "Invalid ephemeral public key format.")
        }
        guard let sharedSecret = try? agreementPrivateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        else { throw .cannotDeriveSharedSecret(name: keyName, error: "Key agreement computation failed.") }

        return sharedSecret.withUnsafeBytes { Data($0) }
    }

    func removeSigningKey(named name: String) throws(KeyStoreError) {
        _ = withKeys { $0.removeValue(forKey: name) }
        saveSigningKeysToStorage()
    }

    func encrypt(data: Data, keyName: String) throws(KeyStoreError) -> Data {
        let publicKeyDER = try getPublicKey(named: keyName)
        let x963Data: Data
        do { x963Data = try P256.Signing.PublicKey(derRepresentation: publicKeyDER).x963Representation } catch {
            throw .cannotGetPublicKey(name: keyName, error: "Cannot convert public key DER to x963: \(error)")
        }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits as String: 256
        ]
        var cfErr: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(x963Data as CFData, attrs as CFDictionary, &cfErr) else {
            throw .cannotGetPublicKey(
                name: keyName,
                error: cfErr?.takeUnretainedValue().localizedDescription ?? "Cannot import public key."
            )
        }
        guard
            let ciphertext = SecKeyCreateEncryptedData(
                secKey,
                .eciesEncryptionCofactorX963SHA256AESGCM,
                data as CFData,
                &cfErr
            )
        else {
            throw .cannotSignData(
                name: keyName,
                error: cfErr?.takeUnretainedValue().localizedDescription ?? "Encryption failed."
            )
        }

        return ciphertext as Data
    }

    func decrypt(encodedData: Data, credential: KeyCredential, keyName: String) throws(KeyStoreError) -> Data {
        guard encodedData.count > 65 + 16 else { throw .invalidPayload }
        guard let wrapper = withKeys({ $0[keyName] }) else {
            throw .cannotGetPublicKey(name: keyName, error: "Key does not exist.")
        }

        if case let .password(pwd) = credential, pwd != wrapper.password { throw .invalidPassword }

        // Import P-256 private key as SecKey for ECIES decryption
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits as String: 256
        ]
        var cfErr: Unmanaged<CFError>?
        guard
            let secKey = SecKeyCreateWithData(
                wrapper.privateKey.x963Representation as CFData,
                attrs as CFDictionary,
                &cfErr
            )
        else {
            throw .decryptionFailed(
                error: cfErr?.takeUnretainedValue().localizedDescription ?? "Cannot import private key."
            )
        }
        guard
            let plaintext = SecKeyCreateDecryptedData(
                secKey,
                .eciesEncryptionCofactorX963SHA256AESGCM,
                encodedData as CFData,
                &cfErr
            )
        else {
            throw .decryptionFailed(
                error: cfErr?.takeUnretainedValue().localizedDescription ?? "Decryption failed."
            )
        }

        return plaintext as Data
    }
}

fileprivate extension SoftwareKeyStore {
    static func loadSigningKeysFromStorage(_ storage: PersistentKeyValueStore) -> [String: KeyWrapper] {
        do {
            return try storage.get(valueFor: PersistentKey(stringLiteral: signingKeysPersistentStorageKey)) ?? [:]
        } catch {
            return [:]
        }
    }

    func saveSigningKeysToStorage() {
        let snapshot = withKeys { $0 }
        do {
            try storage.set(value: snapshot, for: PersistentKey(stringLiteral: signingKeysPersistentStorageKey))
        } catch {
            // We silently ignore this error for now.
        }
    }
}

#endif
