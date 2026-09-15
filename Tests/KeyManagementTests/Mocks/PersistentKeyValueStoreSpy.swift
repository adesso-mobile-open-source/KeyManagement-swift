//
//  PersistentKeyValueStoreSpy.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import Foundation
import PersistentStorage

// We cannot annotate the PersistentKeyValueStore with @Spyable,
// since it has generic functions, which are unsupported by Spyable.

/// Manual spy/mock for PersistentKeyValueStore protocol for use in unit tests.
final class PersistentKeyValueStoreSpy: PersistentKeyValueStore, @unchecked Sendable {
    var encoder: AnyEncoder = JSONEncoder()
    var decoder: AnyDecoder = JSONDecoder()

    private(set) var store: [String: Data] = [:]
    private(set) var setCalls: [(key: String, data: Data)] = []
    private(set) var removeCalls: [String] = []
    private(set) var containsCalls: [String] = []
    private(set) var getDataCalls: [String] = []
    private(set) var getValueCalls: [String] = []

    func contains(valueFor key: PersistentKey) -> Bool {
        containsCalls.append(key.stringValue)
        return store[key.stringValue] != nil
    }

    func get(dataFor key: PersistentKey) throws -> Data? {
        getDataCalls.append(key.stringValue)
        return store[key.stringValue]
    }

    func get<V: Decodable>(valueFor key: PersistentKey) throws -> V? {
        getValueCalls.append(key.stringValue)
        guard let data = store[key.stringValue] else { return nil }
        return try decoder.decode(V.self, from: data)
    }

    func set(data: Data, for key: PersistentKey) throws {
        setCalls.append((key.stringValue, data))
        store[key.stringValue] = data
    }

    func set(value: some Encodable, for key: PersistentKey) throws {
        let data = try encoder.encode(value)
        try set(data: data, for: key)
    }

    func remove(valueFor key: PersistentKey) throws {
        removeCalls.append(key.stringValue)
        store.removeValue(forKey: key.stringValue)
    }
}
