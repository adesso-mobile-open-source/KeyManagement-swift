# Advanced Topics

## Key rotation

There is no dedicated key-rotation API. To rotate a key — generating a new key pair while the old one remains temporarily usable — perform the following steps:

1. Create a new key descriptor with a different name (e.g. append a version suffix).
2. Trigger auto-creation by calling a write operation on the new descriptor.
3. Retrieve and distribute the new public key.
4. Once all encrypted data has been migrated or re-encrypted with the new key, remove the old key.

```swift
struct SigningKeyV1: PasswordProtectedKey { let name = "com.example.signing.v1" }
struct SigningKeyV2: PasswordProtectedKey { let name = "com.example.signing.v2" }

// Create v2
_ = try manager.sign(payload: Data("init".utf8), with: SigningKeyV2(), password: newPassword)

// Migrate: re-sign pending data with v2, verify with v2's public key
// ...

// Remove v1 when migration is complete
try manager.removeKey(SigningKeyV1())
```

> **Note:** There is no way to change the password on an existing key (see [Changing a password](#changing-a-password)). Key rotation is the recommended path for credential changes.

---

## Changing a password

There is no `changePassword` API. The password is baked into the Secure Enclave's access control at key-creation time and cannot be changed after the fact.

To change the password for a ``PasswordProtectedKey``:

1. Sign (or perform any write op) with the **old** key and old password to obtain any data you need.
2. Remove the old key.
3. Call a write op with the new key descriptor and new password — auto-creation generates a fresh key pair.
4. Distribute the new public key.

---

## Concurrency

`KeyManagerImpl` and all its internal stores conform to `Sendable`. It is safe to call `KeyManagerImpl` methods concurrently from multiple Swift concurrency tasks. The Secure Enclave serialises access to the private key internally; no additional locking is required in your code.

Biometric operations (`BiometryAny`, `BiometryCurrentSet`, `UserPresence`) are isolated to the library's `BiometryActor`, a dedicated global actor — **not** `MainActor`. The underlying `Sec*` calls they make (`SecKeyCreateSignature`, `SecKeyCopyKeyExchangeResult`, `SecKeyCreateDecryptedData`, `SecItemCopyMatching`) block the calling thread for as long as the Face ID / Touch ID / passcode prompt is on screen. Apple's own documentation for `SecAccessControlCreateWithFlags` explicitly recommends moving such calls off the main thread rather than performing them there. `BiometryActor` gives these calls a dedicated background execution context so the main thread — and your UI — stays responsive while the system authentication prompt is shown. Call these methods with `await`; Swift hops to `BiometryActor` for you, and there is no need to wrap the call in `MainActor.run` or any other manual dispatch.

---

## Signature format and size

`sign` returns a **DER-encoded P-256 ECDSA signature**. The DER encoding of a P-256 signature is variable-length, typically **70–72 bytes** (never longer than 72 bytes for P-256). The first byte is always `0x30` (DER SEQUENCE tag).

---

## Passcode protection and device passcode requirement

`PasscodeProtectedKey` keys are created with the `.devicePasscode | .privateKeyUsage` access control flags. If the device does not have a passcode set at key-creation time, `createSigningKey` fails and the auto-create path throws `keyCreationFailed`. Ensure the user has set a device passcode before attempting to use a `PasscodeProtectedKey`.

Similarly, `ProtectionMode.whenPasscodeSetThisDeviceOnly` silently **deletes** the keychain item if the user later removes their passcode. If `hasKey` unexpectedly returns `false` for a key created with this protection mode, check whether the device passcode was removed.

---

## App Groups and keychain sharing

KeyManagement does not configure a keychain access group. By default, all keys are stored in the default keychain and are accessible only to the app that created them.

To share keys between an app and its extensions (e.g. a Share Extension, a Widget, or a Notification Service Extension), you must configure keychain sharing in your entitlements and modify the keychain query attributes. This requires changes to the internal `SecureEnclaveKeyStore` implementation and is outside the scope of the public API. Please raise an issue if you require this functionality inside your app.

---

## Default `name` and type renames

The default `name` implementation returns the Swift type name (`String(describing: Self.self)`). This is convenient, but if there is any chance the struct will be renamed later, the data becomes suddenly inaccessible.

If you feel there might be a chance for a type rename, define a permanent identifier instead.

```swift
struct AppSigningKey: PasswordProtectedKey {
    let name = "com.example.app.signing" // frozen — never changes
}
```

---

## `protectionMode` mismatch

The manager persists both the **trait** and the **`protectionMode`** when a key is first auto-created. If you later modify the `protectionMode` in your key descriptor struct without removing the existing key, the next write operation will throw `configurationMismatch`. The fix is the same as for a trait mismatch: remove the key and let it be recreated.

```swift
// Original:
struct MyKey: PasswordProtectedKey {
    let name = "com.example.key"
    let protectionMode = ProtectionMode.whenUnlocked // was this
}

// After change:
struct MyKey: PasswordProtectedKey {
    let name = "com.example.key"
    let protectionMode = ProtectionMode.whenUnlockedThisDeviceOnly // changed
}

// Now the next sign call throws configurationMismatch.
// Fix:
try manager.removeKey(MyKey()) // removes the old key
_ = try manager.sign(...)     // recreates with new protectionMode
```
