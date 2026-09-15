

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
