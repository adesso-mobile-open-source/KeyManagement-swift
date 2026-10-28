//
//  KeyManagerPasscodeTests.swift
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

@Suite("KeyManager — PasscodeProtectedKey") @KeyManagementActor struct KeyManagerPasscodeTests {

    struct TestKey: PasscodeProtectedKey { let name = "TestKey" }

    @Test("Auto-creates key on first sign when absent") func autoCreatesOnFirstSign() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = false
        let mgr = makeManager(store: store)
        _ = try mgr.sign(payload: Data([1]), with: TestKey())
        #expect(store.createCallCount == 1)
    }

    @Test("Does not re-create when key already exists") func doesNotRecreate() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let mgr = makeManager(store: store)
        _ = try mgr.sign(payload: Data([1]), with: TestKey())
        #expect(store.createCallCount == 0)
    }

    @Test("Throws configurationMismatch when trait differs") func throwsConfigMismatch() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let mgr = makeManager(store: store, storedTrait: .password)
        #expect(throws: SignPasscodeError.configurationMismatch(name: "TestKey")) {
            try mgr.sign(payload: Data(), with: TestKey())
        }
    }

    @Test("Decrypt rejects short payload") func decryptRejectsShortPayload() throws {
        let mgr = makeManager(store: KeyStoreSpy())
        #expect(throws: DecryptPasscodeError.invalidPayload) {
            try mgr.decrypt(encodedData: Data(repeating: 0, count: 81), with: TestKey())
        }
    }

    // MARK: - Factory

    private func makeManager(store: KeyStoreSpy, storedTrait: ProtectionTrait? = nil) -> KeyManagerImpl {
        let configStore: KeyConfigurationStore
        if let trait = storedTrait {
            let configuredStore = KeyConfigurationStore(storage: PersistentKeyValueStoreSpy())
            configuredStore.store(
                KeyConfigurationRecord(trait: trait, protectionMode: .whenUnlockedThisDeviceOnly),
                forKeyNamed: "TestKey"
            )
            configStore = configuredStore
        } else {
            configStore = KeyConfigurationStore(storage: PersistentKeyValueStoreSpy())
        }
        return KeyManagerImpl(
            applicationTag: "test",
            keyStore: store,
            configStore: configStore,
            enrollmentMonitor: KeyEnrollmentStateMonitorSpy()
        )
    }
}
