//
//  RemoveKeyError.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import Security

/// Errors thrown by ``KeyManager/removeKey(_:)-swift.method``.
///
/// Removal is idempotent for a key that does not exist — the manager returns
/// without error. This error is thrown only when the keychain delete operation
/// itself fails unexpectedly.
public enum RemoveKeyError: Error, Equatable {
    /// The underlying keychain delete operation failed.
    ///
    /// - Parameters:
    ///   - name: The logical name of the key that could not be removed.
    ///   - status: The raw `OSStatus` returned by the Security framework.
    case removalFailed(name: String, status: OSStatus)
}
