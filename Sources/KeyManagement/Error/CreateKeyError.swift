//
//  CreateKeyError.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// Errors thrown by ``KeyManager/create(key:)-`` and its trait-specific overloads.
///
/// `create` explicitly generates the key pair in the Secure Enclave (or the
/// software key store on the simulator). Use this when you need the public key
/// immediately after creation — for example, to register it with a server —
/// without performing a full signing or decryption round-trip first.
public enum CreateKeyError: Error, Equatable {
    /// A key with the given name already exists in the keystore.
    ///
    /// Remove the existing key with ``KeyManager/removeKey(_:)`` before
    /// creating a new one, or check with ``KeyManager/hasKey(_:)`` first.
    ///
    /// - Parameter name: The logical name of the key that already exists.
    case keyAlreadyExists(name: String)

    /// Key-pair generation failed in the Secure Enclave or software key store.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case creationFailed(name: String, error: String)

    /// The key was created with a different trait than what is now being requested.
    ///
    /// This can happen when the key was previously removed from the keychain but
    /// the configuration record was not cleaned up. Remove the key and retry.
    ///
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
}
