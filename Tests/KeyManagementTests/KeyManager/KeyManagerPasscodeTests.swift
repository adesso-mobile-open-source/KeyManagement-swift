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

@testable import KeyManagement
import PersistentStorage

//
//  KeyManagement
//
import Testing

@Suite("KeyManager — PasscodeProtectedKey") @KeyManagementActor struct KeyManagerPasscodeTests {
    struct TestKey: PasscodeProtectedKey { let name = "TestKey" }

    @Test func `Auto-creates key on first sign when absent`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = false
        let mgr = makeManager(store: store)
        _ = try mgr.sign(payload: Data([1]), with: TestKey())
        #expect(store.createCallCount == 1)
    }

    @Test func `Does not re-create when key already exists`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let mgr = makeManager(store: store)
        _ = try mgr.sign(payload: Data([1]), with: TestKey())
        #expect(store.createCallCount == 0)
    }

    @Test func `Throws configurationMismatch when trait differs`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let mgr = makeManager(store: store, storedTrait: .password)
        #expect(throws: SignPasscodeError.configurationMismatch(name: "TestKey")) {
            try mgr.sign(payload: Data(), with: TestKey())
        }
    }

    @Test func `Decrypt rejects short payload`() throws {
        let mgr = makeManager(store: KeyStoreSpy())
        #expect(throws: DecryptPasscodeError.invalidPayload) {
            try mgr.decrypt(encodedData: Data(repeating: 0, count: 81), with: TestKey())
        }
    }

    @Test func `Sign maps userCancelled store error`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        store.signError = .userCancelled(name: "TestKey")
        let mgr = makeManager(store: store)
        #expect(throws: SignPasscodeError.userCancelled(name: "TestKey")) {
            try mgr.sign(payload: Data(), with: TestKey())
        }
    }

    @Test func `DeriveSharedSecret maps userCancelled store error`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        store.deriveError = .userCancelled(name: "TestKey")
        let mgr = makeManager(store: store)
        #expect(throws: DerivePasscodeError.userCancelled(name: "TestKey")) {
            try mgr.deriveSharedSecret(with: TestKey(), publicKey: Data())
        }
    }

    @Test func `Decrypt maps userCancelled store error`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        store.decryptError = .userCancelled(name: "TestKey")
        let mgr = makeManager(store: store)
        #expect(throws: DecryptPasscodeError.userCancelled(name: "TestKey")) {
            try mgr.decrypt(encodedData: Data(repeating: 0, count: 82), with: TestKey())
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
