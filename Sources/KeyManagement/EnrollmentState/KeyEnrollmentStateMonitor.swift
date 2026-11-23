//
//  KeyEnrollmentStateMonitor.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import LocalAuthentication
import PersistentStorage

// MARK: - Protocol

/// Manages the persisted biometric enrollment baseline for a single key.
///
/// Used exclusively for `BiometryCurrentSetProtectedKey` keys.
/// All operations are synchronous and **prompt-free** — they use
/// `LAContext.canEvaluatePolicy(_:error:)` to read `evaluatedPolicyDomainState`
/// without showing any system UI.
protocol KeyEnrollmentStateMonitor: Sendable {
    /// Persist the current enrollment state as the baseline for this key.
    /// Called automatically by `KeyManager` when a `BiometryCurrentSetProtectedKey`
    /// key is first created.
    func storeEnrollmentState(forKeyNamed name: String)

    /// Compare the current enrollment state to the stored baseline.
    ///
    /// Returns `true` (enrollment changed / key invalid) in two cases:
    /// - Current domain state differs from the stored baseline.
    /// - No baseline has been stored yet (conservative: treat as changed).
    ///
    /// - Throws: `EnrollmentCheckError.lookupFailed` if reading from storage fails.
    func hasEnrollmentChanged(forKeyNamed name: String) throws(EnrollmentCheckError) -> Bool

    /// Remove the stored baseline for this key.
    /// Called automatically by `KeyManager.removeKey(_:)` for CurrentSet keys.
    func clearEnrollmentState(forKeyNamed name: String)
}

// MARK: - Implementation

final class KeyEnrollmentStateMonitorImpl: KeyEnrollmentStateMonitor, Sendable {
    private let storage: PersistentKeyValueStore
    private let contextFactory: @Sendable () -> any PolicyDomainStateEvaluationContext

    /// Production initialiser.
    init(applicationTag: String) {
        storage = PersistentKeyValueStoreImpl(
            dataStore: .userDefaults(
                UserDefaults(suiteName: "\(applicationTag).enrollment_states") ?? .standard
            )
        )
        contextFactory = { LAContext() }
    }

    /// Testable initialiser.
    init(
        storage: PersistentKeyValueStore,
        contextFactory: @escaping @Sendable () -> any PolicyDomainStateEvaluationContext
    ) {
        self.storage = storage
        self.contextFactory = contextFactory
    }

    func storeEnrollmentState(forKeyNamed name: String) {
        let context = contextFactory()
        context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        guard let domainState = context.evaluatedPolicyDomainState else { return }

        try? storage.set(data: domainState, for: storageKey(for: name))
    }

    func hasEnrollmentChanged(forKeyNamed name: String) throws(EnrollmentCheckError) -> Bool {
        let context = contextFactory()
        context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)

        do {
            guard let current = context.evaluatedPolicyDomainState,
                  let stored = try storage.get(dataFor: storageKey(for: name))
            else {
                // No baseline or no current state — treat as changed (conservative).
                return true
            }

            return current != stored
        } catch {
            throw .lookupFailed(error: error.localizedDescription)
        }
    }

    func clearEnrollmentState(forKeyNamed name: String) { try? storage.remove(valueFor: storageKey(for: name)) }

    private func storageKey(for keyName: String) -> PersistentKey {
        PersistentKey(stringLiteral: "\(keyName).enrollment_state")
    }
}
