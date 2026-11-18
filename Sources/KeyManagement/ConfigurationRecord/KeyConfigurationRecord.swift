//
//  KeyConfigurationRecord.swift
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
import PersistentStorage

// MARK: - ProtectionTrait

/// Identifies which key-trait protocol a key was created with.
///
/// Stored alongside the key's `ProtectionMode` in `KeyConfigurationRecord`
/// so `KeyManager` can detect when a caller tries to use a key with a
/// different protection type than it was originally created with.
enum ProtectionTrait: String, Codable, Sendable {
    case password
    case biometryAny
    case biometryCurrentSet
    case passcode
    case userPresence
    case unprotected
}

// MARK: - KeyConfigurationRecord

/// A lightweight record that captures the configuration a key was created with.
///
/// Persisted to a `PersistentKeyValueStore` under the key
/// `"\(keyName).config"` in a dedicated UserDefaults suite at
/// `"\(applicationTag).key_configurations"`.
///
/// On every subsequent write operation (`sign`, `deriveSharedSecret`,
/// `decrypt`) `KeyManager` reads this record and compares it to the
/// `KeyDescriptor` provided by the caller. A mismatch throws
/// `configurationMismatch`.
struct KeyConfigurationRecord: Codable, Sendable {
    let trait: ProtectionTrait
    let protectionMode: ProtectionMode
}

// MARK: - KeyConfigurationStore

/// Manages read/write of `KeyConfigurationRecord` values for a given application tag.
final class KeyConfigurationStore: Sendable {
    private let storage: PersistentKeyValueStore

    init(applicationTag: String) {
        storage = PersistentKeyValueStoreImpl(
            dataStore: .userDefaults(
                UserDefaults(suiteName: "\(applicationTag).key_configurations") ?? .standard
            )
        )
    }

    /// Testable initialiser.
    init(storage: PersistentKeyValueStore) { self.storage = storage }

    func record(forKeyNamed name: String) -> KeyConfigurationRecord? {
        try? storage.get(valueFor: storageKey(for: name))
    }

    func store(_ record: KeyConfigurationRecord, forKeyNamed name: String) {
        try? storage.set(value: record, for: storageKey(for: name))
    }

    func remove(forKeyNamed name: String) { try? storage.remove(valueFor: storageKey(for: name)) }

    private func storageKey(for keyName: String) -> PersistentKey { PersistentKey(stringLiteral: "\(keyName).config") }
}
