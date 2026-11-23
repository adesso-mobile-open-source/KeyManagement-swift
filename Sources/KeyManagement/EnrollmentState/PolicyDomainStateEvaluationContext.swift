//
//  PolicyDomainStateEvaluationContext.swift
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
import Spyable

/// Abstraction over `LAContext` policy evaluation.
///
/// Decouples `KeyEnrollmentStateMonitor` from `LAContext` so the monitor
/// can be tested without real biometric hardware.
///
/// `LAContext` conforms to this protocol via a retroactive extension below.
@Spyable(behindPreprocessorFlag: "DEBUG") protocol PolicyDomainStateEvaluationContext: Sendable {
    /// The opaque bytes identifying the current biometric enrollment.
    /// Non-nil only after `canEvaluatePolicy(_:error:)` has been called
    /// on this instance.
    var evaluatedPolicyDomainState: Data? { get }

    /// Returns whether the given policy can be evaluated on this device.
    /// As a side effect, populates `evaluatedPolicyDomainState`.
    /// This call is **synchronous and prompt-free**.
    @discardableResult func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool
}

extension LAContext: PolicyDomainStateEvaluationContext { }
