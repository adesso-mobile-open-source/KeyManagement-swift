# Getting Started

## Prerequisites

- iOS 16.4 or later
- macOS 13 or later
- Swift 6 / Xcode 15 or later
- A physical iOS device for any trait except `PasswordProtectedKey` and `UnprotectedKey` (the Secure Enclave is not available on the simulator)

## Installation

Add the package dependency to `Package.swift`:

```swift
dependencies: [
    .package(
        url: "https://github.com/adesso-mobile-open-source/KeyManagement-swift",
        from: "1.0.0"
    ),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: ["KeyManagement"]
    ),
]
```

## Core concepts

### Key descriptors

Every key is described by a plain Swift `struct` — called a *key descriptor* — that conforms to one of the six trait protocols. The struct carries no secrets; it only declares the key's name and accessibility class.

```swift
import KeyManagement

struct AppSigningKey: PasswordProtectedKey {
    // Defaults: name = "AppSigningKey", protectionMode = .whenUnlockedThisDeviceOnly
}
```

You can override either default:

```swift
struct AppSigningKey: PasswordProtectedKey {
    let name = "com.example.app.signing"
    let protectionMode: ProtectionMode = .whenUnlockedThisDeviceOnly
}
```

### The `KeyManager` protocol

`KeyManagerImpl` is the production implementation of the `KeyManager` protocol. All public operations are on `KeyManager`. Declare dependencies against the protocol so tests can substitute a spy.

```swift
class AuthService {
    private let keyManager: any KeyManager

    init(keyManager: any KeyManager = KeyManagerImpl(applicationTag: "com.example.app")) {
        self.keyManager = keyManager
    }
}
```

### The application tag

The `applicationTag` namespaces all keys created by a manager instance. Choose a reverse-DNS string unique to your application, e.g. `"com.example.myapp"`. The tag is embedded in each key's keychain application tag as `"\(applicationTag).\(key.name)"`.

> **Important:** Use the same tag value each time you create a `KeyManagerImpl`. If you change it, existing keys in the keychain will not be found.

### Auto-creation

The write operations (`sign`, `deriveSharedSecret`, `decrypt`) create the key automatically on first call if it does not already exist.

### Explicit creation

Call `create(key:)` (or `create(key:password:)` for `PasswordProtectedKey`) when you need the public key immediately — for example, to register it with a server before performing any signing. `create` returns the DER-encoded public key and throws `CreateKeyError.keyAlreadyExists` if the key is already present.

```swift
// Create and immediately get the public key for registration
let publicKeyDER = try manager.create(key: MySigningKey(), password: password)
```

### Read-only operations

`hasKey`, `getPublicKey`, and the plain `encrypt(data:with:)` overload do **not** auto-create. They throw `keyNotFound` (or the trait-specific equivalent) if the key is absent.

For `PasswordProtectedKey`, `encrypt(data:with:generateKeyWithPassword:)` is available as a convenience that auto-creates the key on first call.

## Step-by-step example — password-protected signing key

```swift
import CryptoKit
import KeyManagement

// 1. Define your key
struct MySigningKey: PasswordProtectedKey {
    let name = "com.example.app.signing"
}

// 2. Create the manager
let manager = KeyManagerImpl(applicationTag: "com.example.app")
let password = Data("my-app-password".utf8)

// 3. Sign (auto-creates the key on first call)
let payload = Data("document content".utf8)
let signature = try manager.sign(payload: payload, with: MySigningKey(), password: password)

// 4. Retrieve the public key for verification
let publicKeyDER = try manager.getPublicKey(MySigningKey())
let publicKey = try P256.Signing.PublicKey(derRepresentation: publicKeyDER)
let ecdsaSig  = try P256.Signing.ECDSASignature(derRepresentation: signature)
assert(publicKey.isValidSignature(ecdsaSig, for: payload))

// 5. Remove the key when no longer needed
try manager.removeKey(MySigningKey())
```

## Error handling

Every method uses Swift typed throws, so the compiler tells you exactly which errors are possible. Handle only what can actually happen:

```swift
do {
    let sig = try manager.sign(payload: payload, with: MySigningKey(), password: password)
} catch SignPasswordError.invalidPassword {
    // Wrong password supplied
} catch SignPasswordError.configurationMismatch {
    // A key with this name was created with a different trait — remove and recreate
} catch {
    // signingFailed or keyCreationFailed
}
```

## Protection mode

`ProtectionMode` controls when the OS permits access to the keychain item. The default `.whenUnlockedThisDeviceOnly` is the recommended value for most keys:

| Value                             | Description                                                                       |
| --------------------------------- | --------------------------------------------------------------------------------- |
| `.whenUnlocked`                   | Accessible while device is unlocked. Migrates to new device via encrypted backup. |
| `.whenUnlockedThisDeviceOnly`     | Same, but never migrates. **Default.**                                            |
| `.afterFirstUnlock`               | Accessible after the first unlock since boot (background tasks). Migrates.        |
| `.afterFirstUnlockThisDeviceOnly` | Same, but never migrates.                                                         |
| `.whenPasscodeSetThisDeviceOnly`  | Requires a passcode to be set; deleted if passcode is removed. Never migrates.    |

Override in your key descriptor if needed:

```swift
struct BackgroundKey: UnprotectedKey {
    let name = "com.example.app.background"
    let protectionMode: ProtectionMode = .afterFirstUnlockThisDeviceOnly
}
```
