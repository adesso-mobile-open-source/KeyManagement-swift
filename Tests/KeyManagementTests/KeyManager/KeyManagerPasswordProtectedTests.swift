//
//  KeyManagerPasswordProtectedTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import PersistentStorage
//
//  KeyManagement
//
import Testing

@testable import KeyManagement

@Suite("KeyManager — PasswordProtectedKey") struct KeyManagerPasswordProtectedTests {

    struct TestKey: PasswordProtectedKey { let name = "TestKey" }
    let pwd = Data("secret".utf8)

    @Test("Auto-creates key on first sign when absent") func autoCreatesOnFirstSign() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = false
        store.signStub = Data(repeating: 0xAB, count: 64)
        let mgr = makeManager(store: store)
        _ = try mgr.sign(payload: Data([1]), with: TestKey(), password: pwd)
        #expect(store.createCallCount == 1)
    }

    @Test("Does not re-create when key already exists") func doesNotRecreate() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let mgr = makeManager(store: store)
        _ = try mgr.sign(payload: Data([1]), with: TestKey(), password: pwd)
        #expect(store.createCallCount == 0)
    }

    @Test("Throws configurationMismatch when trait differs") func throwsConfigMismatch() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let mgr = makeManager(store: store, storedTrait: .biometryAny)
        #expect(throws: SignPasswordError.configurationMismatch(name: "TestKey")) {
            try mgr.sign(payload: Data(), with: TestKey(), password: pwd)
        }
    }

    @Test("Maps invalidPassword store error") func mapsInvalidPassword() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        store.signError = .cannotSignDataInvalidPassword(name: "TestKey")
        let mgr = makeManager(store: store)
        #expect(throws: SignPasswordError.invalidPassword(name: "TestKey")) {
            try mgr.sign(payload: Data(), with: TestKey(), password: pwd)
        }
    }

    @Test("Throws keyCreationFailed when auto-create fails") func throwsKeyCreationFailed() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = false
        store.createError = .cannotCreateKey(error: "SE error")
        let mgr = makeManager(store: store)
        #expect(throws: SignPasswordError.self) { try mgr.sign(payload: Data(), with: TestKey(), password: pwd) }
    }

    @Test("Decrypt rejects payload shorter than 82 bytes") func decryptRejectsShortPayload() throws {
        let mgr = makeManager(store: KeyStoreSpy())
        #expect(throws: DecryptPasswordError.invalidPayload) {
            try mgr.decrypt(encodedData: Data(repeating: 0, count: 81), with: TestKey(), password: pwd)
        }
    }

    @Test("removeKey clears config record") func removeKeyClearsConfig() throws {
        let store = KeyStoreSpy()
        let configSpy = PersistentKeyValueStoreSpy()
        let configStore = KeyConfigurationStore(storage: configSpy)
        configStore.store(
            KeyConfigurationRecord(trait: .password, protectionMode: .whenUnlockedThisDeviceOnly),
            forKeyNamed: "TestKey"
        )
        let mgr = makeManager(store: store, configStore: configStore)
        try mgr.removeKey(TestKey())
        #expect(configStore.record(forKeyNamed: "TestKey") == nil)
    }

    // MARK: - Factory

    private func makeManager(
        store: KeyStoreSpy,
        configStore: KeyConfigurationStore? = nil,
        storedTrait: ProtectionTrait? = nil
    ) -> KeyManagerImpl {
        let resolvedStore: KeyConfigurationStore
        if let existing = configStore {
            resolvedStore = existing
        } else if let trait = storedTrait {
            let configuredStore = KeyConfigurationStore(storage: PersistentKeyValueStoreSpy())
            configuredStore.store(
                KeyConfigurationRecord(trait: trait, protectionMode: .whenUnlockedThisDeviceOnly),
                forKeyNamed: "TestKey"
            )
            resolvedStore = configuredStore
        } else {
            resolvedStore = KeyConfigurationStore(storage: PersistentKeyValueStoreSpy())
        }
        return KeyManagerImpl(
            applicationTag: "test",
            keyStore: store,
            configStore: resolvedStore,
            enrollmentMonitor: KeyEnrollmentStateMonitorSpy()
        )
    }
}
