//
//  SecureEnclaveKeyStore.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 20.08.25 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import CryptoKit
import CryptoTokenKit
import Foundation
import LocalAuthentication
import Security

/// A signing key store backed by the Secure Enclave.
final class SecureEnclaveKeyStore: KeyStore {
    // MARK: - Dependencies

    private let security: SecurityProxy

    // MARK: - State

    private let applicationTag: String

    // MARK: - Lifecycle

    public convenience init(applicationTag: String) {
        self.init(applicationTag: applicationTag, security: SecurityProxyImpl())
    }

    init(applicationTag: String, security: SecurityProxy) {
        self.applicationTag = applicationTag
        self.security = security
    }

    // MARK: - KeyStore

    func hasKey(named name: String) throws(KeyStoreError) -> Bool { (try getSecKeyForPublicKey(named: name)) != nil }

    func createSigningKey(named name: String, trait: ProtectionTrait, protectionMode: ProtectionMode, password: Data?)
        throws(KeyStoreError) {
        let options: AuthenticationOptions
        switch trait {
        case .password: options = .applicationPassword.union(.privateKeyUsage)
        case .biometryAny: options = .biometryAny.union(.privateKeyUsage)
        case .biometryCurrentSet: options = .biometryCurrentSet.union(.privateKeyUsage)
        case .passcode: options = .devicePasscode.union(.privateKeyUsage)
        case .userPresence: options = .userPresence.union(.privateKeyUsage)
        case .unprotected: options = .privateKeyUsage
        }

        let accessControl = try Self.run { error in
            security.secAccessControlCreateWithFlags(nil, protectionMode.protectionFlag, options.flags, &error)
        } errorMapper: {
            .cannotCreateKey(error: $0?.localizedDescription ?? "Cannot create access control.")
        }

        let laContext: LAContext? = password.map {
            let ctx = LAContext()
            ctx.setCredential($0, type: .applicationPassword)
            return ctx
        }

        let query = createKeyQuery(name: name, accessControl: accessControl, laContext: laContext)
        _ = try Self.run { error in
            security.secKeyCreateRandomKey(query, &error)
        } errorMapper: {
            .cannotCreateKey(error: $0?.localizedDescription ?? "Cannot create key.")
        }
    }

    func getPublicKey(named name: String) throws(KeyStoreError) -> Data {
        guard let secKey = try getSecKeyForPublicKey(named: name) else {
            throw .cannotGetPublicKey(name: name, error: "Key \(name) does not exist.")
        }

        let cfData = try Self.run { error in
            security.secKeyCopyExternalRepresentation(secKey, &error)
        } errorMapper: { cfError in
            let description = cfError?.localizedDescription ?? "Unknown error converting key to data."
            return .cannotGetPublicKey(name: name, error: description)
        }

        do {
            let x963PublicKeyData = cfData as Data
            return try P256.Signing.PublicKey(x963Representation: x963PublicKeyData).derRepresentation
        } catch { throw .cannotGetPublicKey(name: name, error: "Unknown error converting key to DER data.") }
    }

    func sign(payload: Data, withKeyNamed keyName: String, credential: KeyCredential) throws(KeyStoreError) -> Data {
        let (_, privateKey) = try getKeysForSigning(keyName: keyName, credential: credential)

        let derSignature = try Self.run { error in
            security.secKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, payload as CFData, &error)
        } errorMapper: { cfError in
            Self.handleSigningError(cfError, keyName: keyName)
        }

        return derSignature as Data
    }

    func deriveSharedSecret(withKeyNamed keyName: String, publicKey: Data, credential: KeyCredential)
        throws(KeyStoreError) -> Data {
        let ephemeralAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits as String: 256
        ]

        let ephemeralSecKey = try Self.run { error in
            security.secKeyCreateWithData(publicKey as CFData, ephemeralAttributes as CFDictionary, &error)
        } errorMapper: {
            .cannotDeriveSharedSecret(
                name: keyName,
                error: $0?.localizedDescription ?? "Failed to import ephemeral public key."
            )
        }

        guard let privateKey = try getPrivateKey(named: keyName, credential: credential) else {
            throw .cannotDeriveSharedSecret(name: keyName, error: "Private key not found.")
        }

        let sharedSecretData = try Self.run { error in
            security.secKeyCopyKeyExchangeResult(
                privateKey,
                .ecdhKeyExchangeCofactor,
                ephemeralSecKey,
                [:] as CFDictionary,
                &error
            )
        } errorMapper: { cfError in
            // TKError.corruptedData is raised for both signing and ECDH when the
            // application password is wrong — map it to invalidPassword.
            if let cfError, Self.isInvalidPasswordError(cfError) {
                return .cannotSignDataInvalidPassword(name: keyName)
            }
            return .cannotDeriveSharedSecret(
                name: keyName,
                error: cfError?.localizedDescription ?? "ECDH Key Exchange failed."
            )
        }

        return sharedSecretData as Data
    }

    func removeSigningKey(named name: String) throws(KeyStoreError) {
        guard try hasKey(named: name) else { return }

        try Self.run {
            security.secItemDelete(removeKeyQuery(name: name))
        } errorMapper: {
            .cannotRemoveKey(status: $0)
        }
    }

    func encrypt(data: Data, keyName: String) throws(KeyStoreError) -> Data {
        // getPublicKey returns DER; SecKeyCreateWithData expects x963 (uncompressed).
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

        guard let privateKey = try getPrivateKey(named: keyName, credential: credential) else {
            throw .cannotGetPublicKey(name: keyName, error: "Private key not found.")
        }

        var cfErr: Unmanaged<CFError>?
        guard
            let plaintext = SecKeyCreateDecryptedData(
                privateKey,
                .eciesEncryptionCofactorX963SHA256AESGCM,
                encodedData as CFData,
                &cfErr
            )
        else {
            if let cfError = cfErr?.takeUnretainedValue(), Self.isInvalidPasswordError(cfError) {
                throw .cannotSignDataInvalidPassword(name: keyName)
            }
            throw .decryptionFailed(error: cfErr?.takeUnretainedValue().localizedDescription ?? "Decryption failed.")
        }
        return plaintext as Data
    }
}

// MARK: - Private

extension SecureEnclaveKeyStore {
    fileprivate func laContext(for credential: KeyCredential) -> LAContext? {
        switch credential {
        case .password(let pwd):
            let ctx = LAContext()
            ctx.setCredential(pwd, type: .applicationPassword)
            return ctx
        case .laContext(let ctx): return ctx ?? LAContext()
        case .none: return nil
        }
    }

    fileprivate func getSecKeyForPublicKey(named name: String) throws(KeyStoreError) -> SecKey? {
        var result: CFTypeRef?
        let status = security.secItemCopyMatching(getPublicKeyQuery(name: name), &result)

        if status == errSecItemNotFound { return nil }
        if status != errSecSuccess { throw .cannotGetPublicKey(name: name, error: "OSStatus: \(status)") }
        guard let result else { throw .cannotGetPublicKey(name: name, error: "Invalid key data.") }
        // swiftlint:disable:next force_cast
        return (result as! SecKey)
    }

    fileprivate func getPrivateKey(named name: String, credential: KeyCredential) throws(KeyStoreError) -> SecKey? {
        guard let laCtx = laContext(for: credential) else {
            // No auth context — use query without LAContext for unprotected keys
            let query = getPrivateKeyQueryNoAuth(name: name)
            var result: CFTypeRef?
            let status = security.secItemCopyMatching(query, &result)
            if status == errSecItemNotFound { return nil }
            if status != errSecSuccess {
                throw .cannotSignData(name: name, error: "Failed to retrieve private key. OSStatus: \(status)")
            }
            guard let result else { throw .cannotSignData(name: name, error: "Invalid private key data.") }
            // swiftlint:disable:next force_cast
            return (result as! SecKey)
        }

        let query = getPrivateKeyQuery(name: name, laContext: laCtx)
        var result: CFTypeRef?
        let status = security.secItemCopyMatching(query, &result)

        if status == errSecItemNotFound { return nil }
        if status != errSecSuccess {
            throw .cannotSignData(name: name, error: "Failed to retrieve private key. OSStatus: \(status)")
        }
        guard let result else { throw .cannotSignData(name: name, error: "Invalid private key data.") }
        // swiftlint:disable:next force_cast
        return (result as! SecKey)
    }

    fileprivate func getKeysForSigning(keyName: String, credential: KeyCredential) throws(KeyStoreError) -> (
        publicKeyData: Data, privateKey: SecKey
    ) {
        let publicKeyData = try getPublicKey(named: keyName)

        guard let privateKey = try getPrivateKey(named: keyName, credential: credential) else {
            throw .cannotSignData(name: keyName, error: "Private key \(keyName) does not exist.")
        }

        return (publicKeyData, privateKey)
    }

    fileprivate func tag(forKeyNamed name: String) -> String { "\(applicationTag).\(name)" }

    fileprivate func createKeyQuery(name: String, accessControl: SecAccessControl, laContext: LAContext?)
        -> CFDictionary {
        var dict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true, kSecAttrApplicationTag as String: tag(forKeyNamed: name),
                kSecAttrAccessControl as String: accessControl
            ],
            kSecPublicKeyAttrs as String: [
                kSecAttrIsPermanent as String: true, kSecAttrApplicationTag as String: tag(forKeyNamed: name)
            ]
        ]
        if let ctx = laContext { dict[kSecUseAuthenticationContext as String] = ctx }
        return dict as CFDictionary
    }

    fileprivate func removeKeyQuery(name: String) -> CFDictionary {
        [
            kSecClass as String: kSecClassKey, kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag(forKeyNamed: name)
        ] as CFDictionary
    }

    fileprivate func getPrivateKeyQuery(name: String, laContext: LAContext) -> CFDictionary {
        [
            kSecClass as String: kSecClassKey, kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag(forKeyNamed: name), kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: laContext
        ] as CFDictionary
    }

    fileprivate func getPrivateKeyQueryNoAuth(name: String) -> CFDictionary {
        [
            kSecClass as String: kSecClassKey, kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag(forKeyNamed: name), kSecReturnRef as String: true
        ] as CFDictionary
    }

    fileprivate func getPublicKeyQuery(name: String) -> CFDictionary {
        [
            kSecClass as String: kSecClassKey, kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrApplicationTag as String: tag(forKeyNamed: name), kSecReturnRef as String: true
        ] as CFDictionary
    }

    fileprivate static func run<T>(
        secOperation: (inout Unmanaged<CFError>?) -> T?,
        errorMapper: (CFError?) -> KeyStoreError
    ) throws(KeyStoreError) -> T {
        var error: Unmanaged<CFError>?
        guard let result = secOperation(&error) else { throw errorMapper(error?.takeUnretainedValue()) }
        return result
    }

    fileprivate static func run(secOperation: () -> OSStatus, errorMapper: (OSStatus) -> KeyStoreError)
        throws(KeyStoreError) {
        let status = secOperation()
        if status == errSecSuccess { return }
        throw errorMapper(status)
    }

    fileprivate static func isInvalidPasswordError(_ cfError: CFError) -> Bool {
        let nsError = cfError as Error as NSError
        return nsError.domain == CryptoTokenKit.TKErrorDomain && nsError.code == TKError.Code.corruptedData.rawValue
    }

    fileprivate static func handleSigningError(_ cfError: CFError?, keyName: String) -> KeyStoreError {
        guard let cfError else { return .cannotSignData(name: keyName, error: "Unknown error signing data.") }
        let nsError = cfError as Error as NSError
        if nsError.domain == "com.apple.LocalAuthentication" {
            if nsError.code == LAError.userCancel.rawValue { return .userCancelled(name: keyName) }
            if nsError.code == LAError.biometryLockout.rawValue { return .biometryLockout(name: keyName) }
        }
        if isInvalidPasswordError(cfError) { return .cannotSignDataInvalidPassword(name: keyName) }
        return .cannotSignData(name: keyName, error: cfError.localizedDescription)
    }
}
