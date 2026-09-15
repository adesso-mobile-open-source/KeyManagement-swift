//
//  CanInjectKey.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 22.08.25 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import Foundation

/// Describes a type that can accept externally provisioned private key material.
///
/// Only `SoftwareKeyStore` implements this capability, making it suitable for
/// development and CI environments where deterministic, static keys are required.
///
/// > Warning: Implementations must be considered insecure for production use.
protocol CanInjectKey {
    /// Injects a DER-encoded P-256 private key for a `PasswordProtectedKey`.
    func injectKey<K: PasswordProtectedKey>(_ key: K, password: Data, privateKeyDER: Data) async throws

    /// Injects a DER-encoded P-256 private key for an `UnprotectedKey`.
    func injectKey<K: UnprotectedKey>(_ key: K, privateKeyDER: Data) async throws
}
