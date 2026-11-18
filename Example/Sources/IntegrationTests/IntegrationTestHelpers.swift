//
//  IntegrationTestHelpers.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

// KeyManagementIntegrationTests
//
// These tests run on a REAL DEVICE against the Secure Enclave.
// A human must be present to authenticate biometric/passcode prompts.
//
// Run scheme: KeyManagementIntegrationTests → real iOS device
//
// Application tag used by all tests — change if it conflicts with an
// existing keychain item on your device.
//
import KeyManagement

let integrationAppTag = "de.adesso.KeyManagementIntegrationTests"
