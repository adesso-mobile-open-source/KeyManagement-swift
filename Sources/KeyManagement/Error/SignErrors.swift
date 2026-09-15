//
//  SignErrors.swift
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

/// Errors thrown by ``KeyManager/sign(payload:with:password:)`` for
/// ``PasswordProtectedKey`` keys.
public enum SignPasswordError: Error, Equatable {
    /// A key with this name already exists but was created with a different
    /// protection trait.
    ///
    /// Remove the existing key with ``KeyManager/removeKey(_:)-swift.method``
    /// and recreate it before signing.
    ///
    /// - Parameter name: The logical name of the mismatched key.
    case configurationMismatch(name: String)

    /// The key did not exist and auto-creation failed.
    ///
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)

    /// The signing operation failed for a reason unrelated to the password.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key used in the signing attempt.
    ///   - error: A human-readable description of the underlying error.
    case signingFailed(name: String, error: String)

    /// The supplied `password` does not match the password used when the key
    /// was originally created.
    ///
    /// - Parameter name: The logical name of the key.
    case invalidPassword(name: String)
}

// MARK: - BiometryAnyProtectedKey

/// Errors thrown by ``KeyManager/sign(payload:with:laContext:)-56r5e`` for
/// ``BiometryAnyProtectedKey`` keys.
public enum SignBiometryAnyError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    ///
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)

    /// Auto-creation failed.
    ///
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)

    /// The signing operation failed.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case signingFailed(name: String, error: String)

    /// The user dismissed the biometric prompt.
    ///
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)

    /// Too many consecutive failed biometric attempts; biometry is temporarily
    /// locked out by the system.
    ///
    /// The user must unlock the device with their passcode to clear the lockout.
    ///
    /// - Parameter name: The logical name of the key.
    case biometryLockout(name: String)
}

// MARK: - BiometryCurrentSetProtectedKey

/// Errors thrown by ``KeyManager/sign(payload:with:laContext:)-7zy3t`` for
/// ``BiometryCurrentSetProtectedKey`` keys.
public enum SignBiometryCurrentSetError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    ///
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)

    /// Auto-creation failed.
    ///
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)

    /// The signing operation failed.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case signingFailed(name: String, error: String)

    /// The user dismissed the biometric prompt.
    ///
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)

    /// Too many consecutive failed biometric attempts; biometry is temporarily
    /// locked out.
    ///
    /// - Parameter name: The logical name of the key.
    case biometryLockout(name: String)

    /// The enrolled biometrics changed since the key was created.
    ///
    /// The Secure Enclave has hardware-invalidated the key. Remove it with
    /// ``KeyManager/removeKey(_:)-2b3d0`` and recreate it after prompting the
    /// user to re-authenticate.
    ///
    /// - Parameter name: The logical name of the key.
    case enrollmentChanged(name: String)
}

// MARK: - PasscodeProtectedKey

/// Errors thrown by ``KeyManager/sign(payload:with:)-8nv9u`` for
/// ``PasscodeProtectedKey`` keys.
public enum SignPasscodeError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    ///
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)

    /// Auto-creation failed.
    ///
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)

    /// The signing operation failed.
    ///
    /// This case is also used when the user dismisses the system passcode sheet,
    /// because `PasscodeProtectedKey` operations have no dedicated `userCancelled`
    /// case.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case signingFailed(name: String, error: String)
}

// MARK: - UserPresenceProtectedKey

/// Errors thrown by ``KeyManager/sign(payload:with:laContext:)-3x91n`` for
/// ``UserPresenceProtectedKey`` keys.
public enum SignUserPresenceError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    ///
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)

    /// Auto-creation failed.
    ///
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)

    /// The signing operation failed.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case signingFailed(name: String, error: String)

    /// The user dismissed the biometric or passcode prompt.
    ///
    /// - Parameter name: The logical name of the key.
    case userCancelled(name: String)

    /// Too many consecutive failed biometric attempts; biometry is temporarily
    /// locked out.
    ///
    /// - Parameter name: The logical name of the key.
    case biometryLockout(name: String)
}

// MARK: - UnprotectedKey

/// Errors thrown by ``KeyManager/sign(payload:with:)-7sxwi`` for
/// ``UnprotectedKey`` keys.
public enum SignUnprotectedError: Error, Equatable {
    /// Configuration mismatch — see ``SignPasswordError/configurationMismatch(name:)``.
    ///
    /// - Parameter name: The logical name of the key.
    case configurationMismatch(name: String)

    /// Auto-creation failed.
    ///
    /// - Parameter error: A human-readable description of the creation failure.
    case keyCreationFailed(error: String)

    /// The signing operation failed.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key.
    ///   - error: A human-readable description of the underlying error.
    case signingFailed(name: String, error: String)
}
