//
//  ContentView.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 15.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack {
            Image(systemName: "key.fill")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("KeyManagement Integration Tests")
                .multilineTextAlignment(.center)
                .padding()
            Text("Run the KeyManagementIntegrationTests scheme on a real device to exercise the Secure Enclave.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding()
        }
        .padding()
    }
}
