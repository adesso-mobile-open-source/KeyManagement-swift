# BiometryCurrentSet — Enrollment Change Detection

`BiometryCurrentSetProtectedKey` keys are hardware-invalidated by the Secure Enclave whenever the enrolled biometric set changes. This document explains how to detect and recover from that situation.

## Why enrollment changes matter

When a user adds or removes a fingerprint, or re-enrols Face ID, the iOS Secure Enclave invalidates all keys created with the `biometryCurrentSet` access control flag at the hardware level. Any subsequent attempt to use the private key will fail. Because the Secure Enclave cannot communicate the reason to your app synchronously, you must check *before* attempting an operation.

## Checking for changes — prompt-free

`hasBiometricEnrollmentChanged(for:)` reads the device's current biometric enrollment state and compares it against the baseline that was stored when the key was first created. The check is **synchronous and never shows any system UI**.

```swift
let changed = try manager.hasBiometricEnrollmentChanged(for: MyCurrentSetKey())
```

### Return values

| Value   | Meaning                                                                                                  |
| ------- | -------------------------------------------------------------------------------------------------------- |
| `false` | Enrollment is unchanged. The key should be usable.                                                       |
| `true`  | Enrollment has changed, **or** no baseline exists (e.g. the key has never been created, or was removed). |

The conservative default — returning `true` when no baseline is found — prevents you from silently proceeding with an invalidated key.

## Typical flow

```swift
struct SigningKey: BiometryCurrentSetProtectedKey {
    let name = "com.example.app.currentsetsigning"
}

@KeyManagementActor
func performSignature(payload: Data) async throws -> Data {
    // 1. Check enrollment before attempting to use the key
    let changed = try manager.hasBiometricEnrollmentChanged(for: SigningKey())
    if changed {
        // 2. Remove the (possibly hardware-invalidated) key
        try manager.removeKey(SigningKey())
        // 3. Sign: auto-creates the key and stores a new enrollment baseline.
        //    The first successful sign call after recreation is the real result.
        //
        //    IMPORTANT: Step 2 removed the old key pair entirely, so this
        //    auto-create generates a BRAND-NEW key pair with a NEW public
        //    key — it is not the same key, merely re-enrolled. The old
        //    public key is now permanently invalid. If any third party
        //    (e.g. a backend server) trusts the old public key, you MUST
        //    re-enroll the new public key with that party before relying
        //    on signatures from this key again. Use `getPublicKey(_:)`
        //    (or the return value of `create(key:)`) to obtain the new
        //    public key for re-registration.
        return try manager.sign(payload: payload, with: SigningKey(), laContext: nil)
    }

    // 4. Enrollment unchanged — proceed normally
    return try manager.sign(payload: payload, with: SigningKey(), laContext: nil)
}
```

## When is the baseline stored?

The enrollment baseline is stored automatically the **first time a write operation auto-creates the key** (`sign`, `deriveSharedSecret`, or `decrypt`). You do not store it manually.

## When is the baseline cleared?

The baseline is cleared automatically when you call `removeKey(_:)` on a `BiometryCurrentSetProtectedKey`.

```swift
// Clears the key AND the enrollment baseline
try manager.removeKey(SigningKey()) // uses the BiometryCurrentSetProtectedKey overload
```

## Errors

`hasBiometricEnrollmentChanged(for:)` throws `EnrollmentCheckError.lookupFailed` only if the underlying storage read fails unexpectedly. A missing baseline (key never created, or removed) returns `true` rather than throwing.

## Recommended usage pattern

1. Always call `hasBiometricEnrollmentChanged` at the start of any flow that uses a `BiometryCurrentSetProtectedKey` key.
2. If it returns `true`, remove the key and re-create it as part of your re-authentication flow.
3. Inform the user that they need to re-authenticate because their biometrics changed.
4. **Re-enroll the new public key with any third party that trusted the old one.** Removing and re-creating the key does not preserve the key pair — it generates a brand-new one with a new public key. The old public key is invalidated and can no longer be used to verify signatures or encrypt data for this key. Treat this exactly like a key rotation: fetch the new public key (`getPublicKey(_:)` or the value returned by `create(key:)`) and register it with your server or any other relying party before resuming normal operation.
