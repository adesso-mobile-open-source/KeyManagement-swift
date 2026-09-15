# Testing

## Injecting a mock `KeyManager`

All production code should accept `any KeyManager` rather than a concrete `KeyManagerImpl`. This lets unit tests substitute any conforming type — including a hand-written spy — without touching the Secure Enclave or the keychain.

```swift
// Production type
class AuthService {
    private let keyManager: any KeyManager

    init(keyManager: any KeyManager = KeyManagerImpl(applicationTag: "com.example.app")) {
        self.keyManager = keyManager
    }

    func signChallenge(_ challenge: Data, password: Data) throws -> Data {
        try keyManager.sign(payload: challenge, with: AppSigningKey(), password: password)
    }
}
```

```swift
// In tests
final class KeyManagerSpy: KeyManager, @unchecked Sendable {
    var signStub: Data = Data()
    var signError: (any Error)?
    private(set) var signCallCount = 0

    func sign<K: PasswordProtectedKey>(
        payload: Data, with key: K, password: Data
    ) throws(SignPasswordError) -> Data {
        signCallCount += 1
        if let e = signError as? SignPasswordError { throw e }
        return signStub
    }

    // Provide stub implementations for the remaining protocol requirements...
}

@Test func signChallenge_callsKeyManager() throws {
    let spy = KeyManagerSpy()
    spy.signStub = Data(repeating: 0xAB, count: 64)
    let service = AuthService(keyManager: spy)

    _ = try service.signChallenge(Data("challenge".utf8), password: Data("pw".utf8))

    #expect(spy.signCallCount == 1)
}
```

## Unit-testing without hardware

All six trait protocols compile and run on the simulator because `KeyManagerImpl` automatically uses `SoftwareKeyStore` on the simulator.

**`PasswordProtectedKey` and `UnprotectedKey`** are fully emulated: the password is validated in software and the cryptographic operations use real P-256 keys in memory.

**`BiometryAnyProtectedKey`, `BiometryCurrentSetProtectedKey`, `PasscodeProtectedKey`, and `UserPresenceProtectedKey`** compile and the operations succeed on the simulator, but **no biometric or passcode check is performed**. The `laContext` / credential is silently ignored by `SoftwareKeyStore` and the operation always succeeds. This is useful for exercising your application flow on the simulator, but provides no security guarantee.

KeyManagement comes with **integration tests** on a physical device to verify actual biometric and passcode authentication. See the `Example/` project for its integration test target.

## `ProtectionMode` and `ProtectionTrait` in test assertions

Both types are `Equatable` and `Codable`. You can assert on them directly in Swift Testing:

```swift
#expect(configRecord.trait == .password)
#expect(configRecord.protectionMode == .whenUnlockedThisDeviceOnly)
```

## Integration tests on a real device

The `Example/` directory contains an Xcode project (`KeyManagementExample`) with a `KeyManagementIntegrationTests` target. The target runs inside the host app process with `BUNDLE_LOADER` / `TEST_HOST` configured, giving the tests access to the real Secure Enclave.

To run the integration tests:

1. Open `Example/KeyManagementExample.xcworkspace`.
2. Select the `KeyManagementIntegrationTests` scheme.
3. Set the run destination to a real iOS device.
4. Sit in front of the device — biometric and passcode tests will prompt for authentication.
5. Run (`Cmd+U`).

> **Note:** Integration tests cannot run on the simulator. The test file `TestOnRealDevice.swift` emits a compile-time `#error` if you attempt to build for a simulator target.

## Key cleanup in tests

Each integration test struct cleans up its keys in `init()` and uses `defer { try? manager.removeKey(...) }` inside each test function. This pattern prevents state from leaking between test runs even when a test fails partway through.

```swift
struct MyKeyTests {
    struct TestKey: PasswordProtectedKey { let name = "test.my.key" }

    let manager = KeyManagerImpl(applicationTag: "com.example.test")

    init() {
        // Remove any key left over from a previous run
        try? manager.removeKey(TestKey())
    }

    @Test func someTest() throws {
        defer { try? manager.removeKey(TestKey()) }
        // ... test body
    }
}
```
