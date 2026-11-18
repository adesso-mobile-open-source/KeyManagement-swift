//
//  EncryptErrors.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// Errors thrown by ``KeyManager/encrypt(data:with:)`` and
/// ``KeyManager/encrypt(data:with:generateKeyWithPassword:)``.
///
/// The plain `encrypt` overload is read-only — it does **not** auto-create the
/// key and throws ``keyNotFound`` if the key is absent. The
/// `generateKeyWithPassword` overload creates the key on first call and can
/// additionally throw ``keyCreationFailed``.
public enum EncryptError: Error, Equatable {
    /// No key with the given name exists in the keystore.
    ///
    /// Either call a write operation (`sign`, `deriveSharedSecret`, `decrypt`,
    /// or `create`) first, or use the `encrypt(data:with:generateKeyWithPassword:)`
    /// overload which auto-creates the key.
    ///
    /// - Parameter name: The logical name of the key that was not found.
    case keyNotFound(name: String)

    /// The public key was found in the keystore but could not be retrieved or
    /// imported for encryption.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case retrievalFailed(name: String, error: String)

    /// Encryption with the public key failed.
    ///
    /// This typically indicates a Security framework error during
    /// `SecKeyCreateEncryptedData`.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case encryptionFailed(name: String, error: String)

    /// Auto-creation of the key pair failed.
    ///
    /// Only thrown by the `generateKeyWithPassword` overload when the key does
    /// not yet exist and the Secure Enclave (or software key store) rejects
    /// key-pair generation.
    ///
    /// - Parameter error: A human-readable description of the underlying error.
    case keyCreationFailed(error: String)
}
