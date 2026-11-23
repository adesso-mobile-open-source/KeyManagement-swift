//
//  KeyStore.swift
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

// MARK: - KeyCredential

/// The authentication material for a private-key operation.
enum KeyCredential: Sendable {
    case password(Data)
    case laContext(LAContext?) // nil = store creates its own context
    case none
}

// MARK: - KeyStore (internal)

protocol KeyStore: Sendable {
    func hasKey(named name: String) throws(KeyStoreError) -> Bool

    func createSigningKey(named name: String, trait: ProtectionTrait, protectionMode: ProtectionMode, password: Data?)
        throws(KeyStoreError)

    func getPublicKey(named name: String) throws(KeyStoreError) -> Data

    func sign(payload: Data, withKeyNamed keyName: String, credential: KeyCredential) throws(KeyStoreError) -> Data

    func deriveSharedSecret(withKeyNamed keyName: String, publicKey: Data, credential: KeyCredential)
        throws(KeyStoreError) -> Data

    func removeSigningKey(named name: String) throws(KeyStoreError)

    func encrypt(data: Data, keyName: String) throws(KeyStoreError) -> Data

    func decrypt(encodedData: Data, credential: KeyCredential, keyName: String) throws(KeyStoreError) -> Data
}

// MARK: - KeyStoreError (internal)

enum KeyStoreError: Error, Equatable {
    case cannotGetPublicKey(name: String, error: String)
    case cannotCreateKey(error: String)
    case cannotRemoveKey(status: OSStatus)
    case cannotSignData(name: String, error: String)
    case cannotSignDataInvalidPassword(name: String)
    case cannotDeriveSharedSecret(name: String, error: String)
    case invalidPayload
    case decryptionFailed(error: String)
    case invalidPassword
    case userCancelled(name: String)
    case biometryLockout(name: String)
}

extension KeyStoreError {
    var isInvalidPassword: Bool {
        switch self {
        case .cannotSignDataInvalidPassword, .invalidPassword: true
        default: false
        }
    }

    var isInvalidPayload: Bool {
        if case .invalidPayload = self { return true }
        return false
    }

    var isUserCancelled: Bool {
        if case .userCancelled = self { return true }
        return false
    }

    var isBiometryLockout: Bool {
        if case .biometryLockout = self { return true }
        return false
    }

    var osstatus: OSStatus? {
        if case let .cannotRemoveKey(status) = self { return status }
        return nil
    }
}
