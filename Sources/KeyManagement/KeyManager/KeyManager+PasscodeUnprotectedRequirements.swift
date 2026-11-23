//
//  KeyManager+PasscodeUnprotectedRequirements.swift
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

/// ``KeyManager`` requirements for ``PasscodeProtectedKey`` operations.
///
/// Extracted from ``KeyManager`` to keep individual source files focused.
/// ``KeyManager`` inherits from this protocol, so callers using
/// `any KeyManager` are unaffected.
public protocol KeyManagerPasscodeOperations: Sendable {
    // MARK: - PasscodeProtectedKey

    /// Explicitly creates the key pair for a ``PasscodeProtectedKey`` and returns
    /// the DER-encoded public key.
    ///
    /// The Secure Enclave may present the system passcode UI as part of key
    /// creation, which blocks the calling thread for as long as it is on
    /// screen. Isolated to ``KeyManagementActor`` — never the main actor.
    ///
    /// - Parameter key: A descriptor identifying the key to create.
    /// - Returns: DER-encoded P-256 public key data (91 bytes).
    /// - Throws: ``CreateKeyError``
    @KeyManagementActor func create(key: some PasscodeProtectedKey) throws(CreateKeyError) -> Data

    /// Encrypts `data` using the public key of a ``PasscodeProtectedKey``,
    /// auto-creating the key if it does not yet exist. No authentication required.
    /// - Throws: ``EncryptError``
    func encrypt(data: Data, with key: some PasscodeProtectedKey) throws(EncryptError) -> Data

    /// Signs `payload` using a ``PasscodeProtectedKey``. The system presents its
    /// own passcode UI automatically.
    ///
    /// This call blocks the calling thread for as long as the passcode prompt
    /// is on screen, exactly like biometric authentication. Isolated to
    /// ``KeyManagementActor`` — never the main actor. Call with `await`.
    ///
    /// - Throws: ``SignPasscodeError``
    @KeyManagementActor func sign(payload: Data, with key: some PasscodeProtectedKey) throws(SignPasscodeError) -> Data

    /// Performs ECDH key agreement using a ``PasscodeProtectedKey``. The system
    /// presents its own passcode UI automatically.
    ///
    /// This call blocks the calling thread for as long as the passcode prompt
    /// is on screen, exactly like biometric authentication. Isolated to
    /// ``KeyManagementActor`` — never the main actor. Call with `await`.
    ///
    /// `publicKey` must be an x963-encoded (uncompressed, 65-byte) P-256 key.
    /// - Throws: ``DerivePasscodeError``
    @KeyManagementActor func deriveSharedSecret(
        with key: some PasscodeProtectedKey,
        publicKey: Data
    ) throws(DerivePasscodeError) -> Data

    /// Decrypts ECIES data using a ``PasscodeProtectedKey``. The system presents
    /// its own passcode UI automatically.
    ///
    /// This call blocks the calling thread for as long as the passcode prompt
    /// is on screen, exactly like biometric authentication. Isolated to
    /// ``KeyManagementActor`` — never the main actor. Call with `await`.
    ///
    /// - Throws: ``DecryptPasscodeError``
    @KeyManagementActor func decrypt(
        encodedData: Data,
        with key: some PasscodeProtectedKey
    ) throws(DecryptPasscodeError) -> Data
}

/// ``KeyManager`` requirements for ``UnprotectedKey`` operations.
///
/// Extracted from ``KeyManager`` to keep individual source files focused.
/// ``KeyManager`` inherits from this protocol, so callers using
/// `any KeyManager` are unaffected.
public protocol KeyManagerUnprotectedOperations: Sendable {
    // MARK: - UnprotectedKey

    /// Explicitly creates the key pair for an ``UnprotectedKey`` and returns
    /// the DER-encoded public key. No authentication required.
    ///
    /// - Parameter key: A descriptor identifying the key to create.
    /// - Returns: DER-encoded P-256 public key data (91 bytes).
    /// - Throws: ``CreateKeyError``
    func create(key: some UnprotectedKey) throws(CreateKeyError) -> Data

    /// Encrypts `data` using the public key of an ``UnprotectedKey``,
    /// auto-creating the key if it does not yet exist. No authentication required.
    /// - Throws: ``EncryptError``
    func encrypt(data: Data, with key: some UnprotectedKey) throws(EncryptError) -> Data

    /// Signs `payload` using an ``UnprotectedKey``. No authentication required.
    ///
    /// - Throws: ``SignUnprotectedError``
    func sign(payload: Data, with key: some UnprotectedKey) throws(SignUnprotectedError) -> Data

    /// Performs ECDH key agreement using an ``UnprotectedKey``. No authentication
    /// required.
    ///
    /// `publicKey` must be an x963-encoded (uncompressed, 65-byte) P-256 key.
    /// - Throws: ``DeriveUnprotectedError``
    func deriveSharedSecret(with key: some UnprotectedKey, publicKey: Data) throws(DeriveUnprotectedError) -> Data

    /// Decrypts ECIES data using an ``UnprotectedKey``. No authentication required.
    ///
    /// - Throws: ``DecryptUnprotectedError``
    func decrypt(encodedData: Data, with key: some UnprotectedKey) throws(DecryptUnprotectedError) -> Data
}
