//
//  KeyManagerReadOnlyTests.swift
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

@Suite("KeyManager — read-only operations") struct KeyManagerReadOnlyTests {
    struct AKey: PasswordProtectedKey { }

    @Test func `hasKey forwards to backing store`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        let mgr = makeManager(store: store)
        #expect(try mgr.hasKey(AKey()) == true)
        #expect(store.hasKeyCallCount == 1)
    }

    @Test func `hasKey maps store error to lookupFailed`() throws {
        let store = KeyStoreSpy()
        store.hasKeyError = .cannotGetPublicKey(name: "AKey", error: "oops")
        let mgr = makeManager(store: store)
        #expect(throws: HasKeyError.self) { try mgr.hasKey(AKey()) }
    }

    @Test func `getPublicKey throws keyNotFound when absent`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = false
        let mgr = makeManager(store: store)
        #expect(throws: GetPublicKeyError.keyNotFound(name: "AKey")) { try mgr.getPublicKey(AKey()) }
    }

    @Test func `getPublicKey returns data when present`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = true
        store.getPublicKeyStub = Data([0x30, 0x01])
        let mgr = makeManager(store: store)
        let data = try mgr.getPublicKey(AKey())
        #expect(data == Data([0x30, 0x01]))
    }

    @Test func `encrypt throws keyNotFound when absent`() throws {
        let store = KeyStoreSpy()
        store.hasKeyStub = false
        let mgr = makeManager(store: store)
        #expect(throws: EncryptError.keyNotFound(name: "AKey")) {
            try mgr.encrypt(data: Data([1, 2, 3]), with: AKey())
        }
    }

    @Test func `removeKey calls store and clears config`() throws {
        let store = KeyStoreSpy()
        let configSpy = PersistentKeyValueStoreSpy()
        let configStore = KeyConfigurationStore(storage: configSpy)
        configStore.store(
            KeyConfigurationRecord(trait: .password, protectionMode: .whenUnlockedThisDeviceOnly),
            forKeyNamed: "AKey"
        )
        let mgr = makeManager(store: store, configStore: configStore)
        try mgr.removeKey(AKey())
        #expect(store.removeCallCount == 1)
        #expect(configStore.record(forKeyNamed: "AKey") == nil)
    }

    // MARK: - Factory

    private func makeManager(store: KeyStoreSpy, configStore: KeyConfigurationStore? = nil) -> KeyManagerImpl {
        KeyManagerImpl(
            applicationTag: "test",
            keyStore: store,
            configStore: configStore ?? KeyConfigurationStore(storage: PersistentKeyValueStoreSpy()),
            enrollmentMonitor: KeyEnrollmentStateMonitorSpy()
        )
    }
}
