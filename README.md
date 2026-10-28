# KeyManagement

A Swift library for hardware-backed cryptographic key management on iOS, built on top of the Secure Enclave.

## What it does

KeyManagement lets you create, use, and remove P-256 elliptic-curve key pairs whose private keys are bound to a specific device and protected by a user-chosen authentication policy. The private key never leaves the Secure Enclave. Operations available per key:

- **Sign** — produce a DER-encoded ECDSA signature (P-256, SHA-256)
- **Derive shared secret** — perform ECDH key agreement (for symmetric key derivation or hybrid encryption)
- **Encrypt / Decrypt** — ECIES using the Apple `eciesEncryptionCofactorX963SHA256AESGCM` scheme
- **Get public key** — export the DER-encoded P-256 public key for sharing

## What it does not do

- It does not manage symmetric keys, certificates, or key chains.
- It does not perform hashing, MAC computation, or arbitrary data transformation.
- It does not store secrets outside the Secure Enclave (passwords, tokens, etc.).
- It does not provide networking, server attestation, or remote key agreement.
- It does not support importing private key material into the Secure Enclave (hardware limitation).

## Requirements

- iOS 16.4+
- macOS 13+
- Xcode 15+ / Swift 6+
- A physical device for biometric and passcode-protected keys (Secure Enclave not available on the simulator)

## Installation

Add the package to your `Package.swift`:

```swift
.package(url: "git@gitlab.adesso-group.com:ams/intern/ios/foundation-libs/keymanagement.git", from: "1.0.0")
```

Then add `"KeyManagement"` to your target's dependencies.

## Quick start

### 1. Define a key

A key is a lightweight `struct` that conforms to one of the key-trait protocols. The struct declares what name the key lives under and how it is protected.

```swift
import KeyManagement

struct AppSigningKey: PasswordProtectedKey {
    let name = "com.example.app.signing"
}
```

### 2. Create the manager

```swift
let manager = KeyManagerImpl(applicationTag: "com.example.app")
```

### 3. Sign data

On first call the key is created automatically.

```swift
let payload = Data("hello".utf8)
let password = Data("my-password".utf8)

let signature = try manager.sign(payload: payload, with: AppSigningKey(), password: password)
```

### 4. Verify the signature

`getPublicKey` returns a DER-encoded P-256 public key you can share with any party that understands ECDSA-P256.

```swift
import CryptoKit

let pubKeyDER = try manager.getPublicKey(AppSigningKey())
let publicKey = try P256.Signing.PublicKey(derRepresentation: pubKeyDER)
let ecdsaSig  = try P256.Signing.ECDSASignature(derRepresentation: signature)
publicKey.isValidSignature(ecdsaSig, for: payload) // true
```

## Key protection traits

| Protocol                         | Authentication                       | `KeyManagementActor` isolation |
| -------------------------------- | ------------------------------------ | ------------------------- |
| `PasswordProtectedKey`           | Application-supplied `Data` password | No                        |
| `BiometryAnyProtectedKey`        | Face ID / Touch ID (any enrolled)    | Yes                       |
| `BiometryCurrentSetProtectedKey` | Currently enrolled biometrics        | Yes                       |
| `PasscodeProtectedKey`           | Device passcode (system UI)          | Yes                       |
| `UserPresenceProtectedKey`       | Biometry with passcode fallback      | Yes                       |
| `UnprotectedKey`                 | None — device possession only        | No                        |

Operations marked "Yes" are isolated to the library's `KeyManagementActor` — a dedicated background actor, not `MainActor`. Their underlying Secure Enclave calls block until the biometric/passcode prompt is dismissed, so they must never run on the main actor. Call them with `await`. See [Concurrency](docs/advanced.md#concurrency) for details.

See [docs/key-traits.md](docs/key-traits.md) for a detailed comparison.

## Parameterised key names — `@KeyName`

Use the `@KeyName` macro when the key name must embed runtime parameters:

```swift
@KeyName("account/{accountId}/signing")
struct AccountSigningKey: PasswordProtectedKey {}

// Usage:
let key = AccountSigningKey(accountId: "user-42")
// key.name == "account/user-42/signing"
```

See [docs/key-name-macro.md](docs/key-name-macro.md) for details.

## Testing

Inject `any KeyManager` so tests can substitute a spy without touching the Secure Enclave.

```swift
class MyService {
    private let keyManager: any KeyManager

    init(keyManager: any KeyManager = KeyManagerImpl(applicationTag: "com.example.app")) {
        self.keyManager = keyManager
    }
}
```

See [docs/testing.md](docs/testing.md) for a complete guide.

## Further reading

- [Getting Started](docs/getting-started.md) — step-by-step setup
- [Key Traits](docs/key-traits.md) — choosing the right protection
- [Biometry (Current Set)](docs/biometry-current-set.md) — enrollment change detection
- [Encrypt / Decrypt](docs/encrypt-decrypt.md) — ECIES hybrid encryption
- [KeyName Macro](docs/key-name-macro.md) — parameterised key names
- [Testing](docs/testing.md) — unit-testing without hardware
- [Advanced Topics](docs/advanced.md) — key rotation, password change, concurrency, signature format, App Groups
