//
//  HasKeyError.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

/// Errors thrown by ``KeyManager/hasKey(_:)``.
///
/// This error type has only one case because `hasKey` is a simple existence
/// check; the only unexpected situation is a keychain query failure.
public enum HasKeyError: Error, Equatable {
    /// The underlying keychain lookup failed with an unexpected error.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key that was being checked.
    ///   - error: A human-readable description of the underlying error, typically
    ///     an `OSStatus` description from the Security framework.
    case lookupFailed(name: String, error: String)
}
