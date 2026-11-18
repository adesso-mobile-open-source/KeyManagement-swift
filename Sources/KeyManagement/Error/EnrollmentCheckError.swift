//
//  EnrollmentCheckError.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// Errors thrown by ``KeyManager/hasBiometricEnrollmentChanged(for:)``.
///
/// This method is prompt-free. A thrown error indicates a storage read failure,
/// not a biometric authentication failure.
public enum EnrollmentCheckError: Error, Equatable {
    /// Reading or comparing the stored enrollment baseline failed.
    ///
    /// This is an unexpected condition. The `hasEnrollmentChanged` result is
    /// conservatively `true` (treat as changed) when no baseline exists, so a
    /// missing baseline is not an error — only a storage read failure is.
    ///
    /// - Parameter error: A human-readable description of the underlying error.
    case lookupFailed(error: String)
}
