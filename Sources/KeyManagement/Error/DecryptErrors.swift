//
//  DecryptErrors.swift
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

// MARK: - PasswordProtectedKey

/// Errors thrown by ``KeyManager/decrypt(encodedData:with:password:)`` for
/// ``PasswordProtectedKey`` keys.
public enum DecryptPasswordError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    case keyCreationFailed(error: String)

    /// The `encodedData` is too short to be a valid ECIES payload.
    ///
    /// A valid payload must contain at least 82 bytes: 65 bytes for the
    /// uncompressed ephemeral public key, 16 bytes for the AES-GCM authentication
    /// tag, and at least 1 byte of ciphertext.
    case invalidPayload

    /// Decryption failed.
    ///
    /// This typically means the ciphertext was not produced by ``KeyManager/encrypt(data:with:)``
    /// for this key, or the key has been rotated since the data was encrypted.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case decryptionFailed(name: String, error: String)

    /// The supplied `password` does not match the password used when the key
    /// was originally created.
    ///
    /// - Parameter name: The logical name of the key.
    case invalidPassword(name: String)
}

// MARK: - BiometryAnyProtectedKey

/// Errors thrown by ``KeyManager/decrypt(encodedData:with:laContext:)-5c7w9``
/// for ``BiometryAnyProtectedKey`` keys.
public enum DecryptBiometryAnyError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// Payload too short. See ``DecryptPasswordError/invalidPayload``.
    case invalidPayload
    /// Decryption failed.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case decryptionFailed(name: String, error: String)
    /// The user dismissed the biometric prompt.
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)
    /// Too many failed biometric attempts; biometry is locked out.
    /// - Parameter name: The logical name of the key.
    case biometryLockout(name: String)
}

// MARK: - BiometryCurrentSetProtectedKey

/// Errors thrown by ``KeyManager/decrypt(encodedData:with:laContext:)-8r1j0``
/// for ``BiometryCurrentSetProtectedKey`` keys.
public enum DecryptBiometryCurrentSetError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// Payload too short. See ``DecryptPasswordError/invalidPayload``.
    case invalidPayload
    /// Decryption failed.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case decryptionFailed(name: String, error: String)
    /// The user dismissed the biometric prompt.
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)
    /// Too many failed biometric attempts; biometry is locked out.
    /// - Parameter name: The logical name of the key.
    case biometryLockout(name: String)
    /// Biometrics changed since key creation; key is hardware-invalidated.
    /// Remove with ``KeyManager/removeKey(_:)-2b3d0`` and recreate.
    /// - Parameter name: The logical name of the key.
    case enrollmentChanged(name: String)
}

// MARK: - PasscodeProtectedKey

/// Errors thrown by ``KeyManager/decrypt(encodedData:with:)-8yai1`` for
/// ``PasscodeProtectedKey`` keys.
public enum DecryptPasscodeError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// Payload too short. See ``DecryptPasswordError/invalidPayload``.
    case invalidPayload
    /// Decryption failed for a reason unrelated to user cancellation.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case decryptionFailed(name: String, error: String)
    /// The user dismissed the system passcode sheet.
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)
}

// MARK: - UserPresenceProtectedKey

/// Errors thrown by ``KeyManager/decrypt(encodedData:with:laContext:)-4cgaj``
/// for ``UserPresenceProtectedKey`` keys.
public enum DecryptUserPresenceError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// Payload too short. See ``DecryptPasswordError/invalidPayload``.
    case invalidPayload
    /// Decryption failed.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case decryptionFailed(name: String, error: String)
    /// The user dismissed the biometric or passcode prompt.
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)
    /// Too many failed biometric attempts; biometry is locked out.
    /// - Parameter name: The logical name of the key.
    case biometryLockout(name: String)
}

// MARK: - UnprotectedKey

/// Errors thrown by ``KeyManager/decrypt(encodedData:with:)-63gjp`` for
/// ``UnprotectedKey`` keys.
public enum DecryptUnprotectedError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// Payload too short. See ``DecryptPasswordError/invalidPayload``.
    case invalidPayload
    /// Decryption failed.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case decryptionFailed(name: String, error: String)
}
