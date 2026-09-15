//
//  KeyManagerBiometryCurrentSetTests.swift
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

@Suite("KeyManager — BiometryCurrentSetProtectedKey") struct KeyManagerBiometryCurrentSetTests {

    struct TestKey: BiometryCurrentSetProtectedKey { let name = "TestKey" }

    @Test("Auto-creates key and stores enrollment baseline on first sign") @BiometryActor
    func autoCreatesAndStoresBaseline() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = false
        let monitor = KeyEnrollmentStateMonitorSpy()
        let mgr = makeManager(store: store, monitor: monitor)
        _ = try mgr.sign(payload: Data([1]), with: TestKey(), laContext: nil)
        #expect(store.createCallCount == 1)
        #expect(monitor.storeCallCount == 1)
    }

    @Test("Does not re-create when key already exists") @BiometryActor func doesNotRecreate() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let monitor = KeyEnrollmentStateMonitorSpy()
        monitor.hasChangedStub = false
        let mgr = makeManager(store: store, monitor: monitor)
        _ = try mgr.sign(payload: Data([1]), with: TestKey(), laContext: nil)
        #expect(store.createCallCount == 0)
    }

    @Test("Throws enrollmentChanged when enrollment has changed") @BiometryActor func throwsEnrollmentChanged() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let monitor = KeyEnrollmentStateMonitorSpy()
        monitor.hasChangedStub = true
        let mgr = makeManager(store: store, monitor: monitor)
        #expect(throws: SignBiometryCurrentSetError.enrollmentChanged(name: "TestKey")) {
            try mgr.sign(payload: Data(), with: TestKey(), laContext: nil)
        }
    }

    @Test("Throws configurationMismatch when trait differs") @BiometryActor func throwsConfigMismatch() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let mgr = makeManager(store: store, storedTrait: .password)
        #expect(throws: SignBiometryCurrentSetError.configurationMismatch(name: "TestKey")) {
            try mgr.sign(payload: Data(), with: TestKey(), laContext: nil)
        }
    }

    @Test("removeKey clears config and enrollment baseline")
    @BiometryActor func removeKeyClearsConfigAndBaseline() throws {
        let store = KeyStoreSpy()
        let monitor = KeyEnrollmentStateMonitorSpy()
        let mgr = makeManager(store: store, monitor: monitor)
        try mgr.removeKey(TestKey())
        #expect(store.removeCallCount == 1)
        #expect(monitor.clearCallCount == 1)
    }

    @Test("hasBiometricEnrollmentChanged delegates to monitor")
    @BiometryActor func hasBiometricEnrollmentChanged() throws {
        let monitor = KeyEnrollmentStateMonitorSpy()
        monitor.hasChangedStub = true
        let mgr = makeManager(store: KeyStoreSpy(), monitor: monitor)
        #expect(try mgr.hasBiometricEnrollmentChanged(for: TestKey()) == true)
    }

    @Test("Decrypt rejects short payload")
    @BiometryActor func decryptRejectsShortPayload() throws {
        let mgr = makeManager(store: KeyStoreSpy())
        #expect(throws: DecryptBiometryCurrentSetError.invalidPayload) {
            try mgr.decrypt(encodedData: Data(repeating: 0, count: 81), with: TestKey(), laContext: nil)
        }
    }

    // MARK: - Factory

    private func makeManager(
        store: KeyStoreSpy,
        monitor: KeyEnrollmentStateMonitorSpy? = nil,
        storedTrait: ProtectionTrait? = nil
    ) -> KeyManagerImpl {
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
            enrollmentMonitor: monitor ?? KeyEnrollmentStateMonitorSpy()
        )
    }
}
