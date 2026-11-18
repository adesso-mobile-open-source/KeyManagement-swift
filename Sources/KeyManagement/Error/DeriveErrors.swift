//
//  DeriveErrors.swift
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

/// Errors thrown by ``KeyManager/deriveSharedSecret(with:publicKey:password:)``
/// for ``PasswordProtectedKey`` keys.
public enum DerivePasswordError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    case configurationMismatch(name: String)

    /// Auto-creation failed.
    ///
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)

    /// The ECDH key agreement failed.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case derivationFailed(name: String, error: String)

    /// The supplied `password` does not match the password used when the key
    /// was originally created.
    ///
    /// - Parameter name: The logical name of the key.
    case invalidPassword(name: String)
}

// MARK: - BiometryAnyProtectedKey

/// Errors thrown by ``KeyManager/deriveSharedSecret(with:publicKey:laContext:)-7rp46``
/// for ``BiometryAnyProtectedKey`` keys.
public enum DeriveBiometryAnyError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// The ECDH key agreement failed.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case derivationFailed(name: String, error: String)
    /// The user dismissed the biometric prompt.
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)
    /// Too many failed biometric attempts; biometry is locked out.
    /// - Parameter name: The logical name of the key.
    case biometryLockout(name: String)
}

// MARK: - BiometryCurrentSetProtectedKey

/// Errors thrown by ``KeyManager/deriveSharedSecret(with:publicKey:laContext:)-6kzjz``
/// for ``BiometryCurrentSetProtectedKey`` keys.
public enum DeriveBiometryCurrentSetError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// The ECDH key agreement failed.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case derivationFailed(name: String, error: String)
    /// The user dismissed the biometric prompt.
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)
    /// Too many failed biometric attempts; biometry is locked out.
    /// - Parameter name: The logical name of the key.
    case biometryLockout(name: String)
    /// The enrolled biometrics changed since the key was created; the key is
    /// hardware-invalidated. Remove and recreate.
    /// - Parameter name: The logical name of the key.
    case enrollmentChanged(name: String)
}

// MARK: - PasscodeProtectedKey

/// Errors thrown by ``KeyManager/deriveSharedSecret(with:publicKey:)-3pxc8``
/// for ``PasscodeProtectedKey`` keys.
public enum DerivePasscodeError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// The ECDH key agreement failed for a reason unrelated to user cancellation.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case derivationFailed(name: String, error: String)
    /// The user dismissed the system passcode sheet.
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)
}

// MARK: - UserPresenceProtectedKey

/// Errors thrown by ``KeyManager/deriveSharedSecret(with:publicKey:laContext:)-2apx0``
/// for ``UserPresenceProtectedKey`` keys.
public enum DeriveUserPresenceError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// The ECDH key agreement failed.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case derivationFailed(name: String, error: String)
    /// The user dismissed the biometric or passcode prompt.
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)
    /// Too many failed biometric attempts; biometry is locked out.
    /// - Parameter name: The logical name of the key.
    case biometryLockout(name: String)
}

// MARK: - UnprotectedKey

/// Errors thrown by ``KeyManager/deriveSharedSecret(with:publicKey:)-5p5e8``
/// for ``UnprotectedKey`` keys.
public enum DeriveUnprotectedError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)
    /// Auto-creation failed.
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)
    /// The ECDH key agreement failed.
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case derivationFailed(name: String, error: String)
}
