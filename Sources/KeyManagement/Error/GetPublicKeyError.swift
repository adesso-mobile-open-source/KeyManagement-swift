//
//  GetPublicKeyError.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// Errors thrown by ``KeyManager/getPublicKey(_:)``.
///
/// `getPublicKey` does not auto-create — a write operation (`sign`,
/// `deriveSharedSecret`, or `decrypt`) must have been called at least once
/// before calling `getPublicKey`.
public enum GetPublicKeyError: Error, Equatable {
    /// No key with the given name exists in the keystore.
    ///
    /// Call any write operation first to auto-create the key, then retry.
    ///
    /// - Parameter name: The logical name of the key that was not found.
    case keyNotFound(name: String)

    /// The key exists but its public key bytes could not be retrieved or
    /// converted to DER format.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case retrievalFailed(name: String, error: String)
}
