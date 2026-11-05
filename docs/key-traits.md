# Key Traits

Each key descriptor conforms to exactly one of the six trait protocols. The trait determines:

1. **Which authentication factor** the Secure Enclave requires before permitting a private-key operation.
2. **Which credential parameter** appears on the `KeyManager` methods.
3. **Whether the operation is isolated to `KeyManagementActor`** (biometric and passcode traits perform a blocking, authentication-gated Secure Enclave call that must never run on the main thread — see [Concurrency](advanced.md#concurrency)).

---

## `PasswordProtectedKey`

**Access control flags:** `applicationPassword | privateKeyUsage`

The private key is protected by an application-supplied byte sequence (the "password"). The password is set on an `LAContext` and presented to the Secure Enclave at the time of each private-key operation. The Secure Enclave validates the password without any system UI.

**Credential parameter:** `password: Data`

**`KeyManagementActor` isolation:** No — all operations are synchronous and show no system UI.

**Simulator support:** Yes — `SoftwareKeyStore` emulates this trait; the password check is a byte-equality comparison in software.

```swift
struct AppKey: PasswordProtectedKey {
    let name = "com.example.app.key"
}

let password = Data("s3cr3t".utf8)

// sign auto-creates the key on first call
let signature = try manager.sign(payload: data, with: AppKey(), password: password)
```

---

## `BiometryAnyProtectedKey`

**Access control flags:** `biometryAny | privateKeyUsage`

The private key requires biometric authentication (Face ID or Touch ID). The key remains usable if additional fingers are enrolled or Face ID is re-enrolled — it only becomes invalid if *all* biometrics are reset.

**Credential parameter:** `laContext: LAContext?`

- Pass `nil` to let the system present a biometric prompt automatically.
- Pass a pre-evaluated `LAContext` to avoid a second prompt when you have already authenticated for another reason.

**`KeyManagementActor` isolation:** Yes — `create`, `sign`, `deriveSharedSecret`, and `decrypt` are isolated to `KeyManagementActor`, a dedicated background actor. Their underlying `Sec*` calls block until the biometric prompt is dismissed, so they must never run on the main actor.

**Simulator support:** Yes, with limitations — the operation compiles and succeeds on the simulator, but no biometric check is performed. The `laContext` credential is ignored by `SoftwareKeyStore` and the private-key operation always succeeds silently. Run integration tests on a real device to verify actual biometric authentication.

```swift
struct BiometricKey: BiometryAnyProtectedKey {
    let name = "com.example.app.biometric"
}

// Let the system prompt the user. `sign` is isolated to `KeyManagementActor`,
// so `await` hops off the main thread automatically.
let signature = try await manager.sign(payload: data, with: BiometricKey(), laContext: nil)

// Or pass a pre-evaluated context to avoid a second prompt
let ctx = LAContext()
try await ctx.evaluatePolicy(
    .deviceOwnerAuthenticationWithBiometrics,
    localizedReason: "Authenticate to sign"
)
let signature = try await manager.sign(payload: data, with: BiometricKey(), laContext: ctx)
```

---

## `BiometryCurrentSetProtectedKey`

**Access control flags:** `biometryCurrentSet | privateKeyUsage`

Like `BiometryAnyProtectedKey`, but the key is hardware-invalidated when the enrolled biometric set changes — for example, when a new finger is added, an existing finger is removed, or Face ID is re-enrolled.

**Credential parameter:** `laContext: LAContext?` — same as `BiometryAnyProtectedKey`.

**`KeyManagementActor` isolation:** Yes.

**Simulator support:** Yes, with limitations — the operation compiles and succeeds on the simulator, but no biometric check is performed. The `laContext` credential is ignored by `SoftwareKeyStore` and the private-key operation always succeeds silently. Additionally, `hasBiometricEnrollmentChanged(for:)` will always return `true` on the simulator because `LAContext.evaluatedPolicyDomainState` is `nil` without real biometric hardware. Run integration tests on a real device for meaningful behaviour.

**Enrollment change detection:** Call `hasBiometricEnrollmentChanged(for:)` *before* any private-key operation to detect invalidation without triggering a biometric prompt. If it returns `true`, remove the key and let the user re-create it.

```swift
if try manager.hasBiometricEnrollmentChanged(for: CurrentSetKey()) {
    try manager.removeKey(CurrentSetKey())
    // Prompt the user to re-authenticate and re-register
}
```

See [biometry-current-set.md](biometry-current-set.md) for a complete guide.

---

## `PasscodeProtectedKey`

**Access control flags:** `devicePasscode | privateKeyUsage`

The private key is protected by the device passcode. The system presents its own passcode entry UI; no credential parameter appears in the API.

**Credential parameter:** None.

**`KeyManagementActor` isolation:** Yes — `create`, `sign`, `deriveSharedSecret`, and `decrypt` are isolated to `KeyManagementActor`. The `.devicePasscode` access control shows the same kind of blocking system UI as biometry, and the underlying `Sec*` calls block the calling thread for as long as the passcode prompt is on screen, so these operations must never run on the main actor. (`encrypt` is the exception — it only uses the public key and remains synchronous.)

**Simulator support:** Yes, with limitations — the operation compiles and succeeds on the simulator, but no passcode check is performed and no system UI is shown. The credential is ignored by `SoftwareKeyStore` and the private-key operation always succeeds silently. Run integration tests on a real device to verify actual passcode authentication.

**Note on cancellation:** `SignPasscodeError`, `DerivePasscodeError`, and `DecryptPasscodeError` each have a dedicated `userCancelled` case. When the user dismisses the system passcode sheet, the manager maps the underlying Security framework error to `userCancelled` instead of `signingFailed` / `derivationFailed` / `decryptionFailed`, so consumers can reliably distinguish cancellation from other failures.

```swift
struct PasscodeKey: PasscodeProtectedKey {
    let name = "com.example.app.passcode"
}

// System shows passcode UI automatically. `sign` is isolated to
// KeyManagementActor, so it must be awaited.
let signature = try await manager.sign(payload: data, with: PasscodeKey())
```

---

## `UserPresenceProtectedKey`

**Access control flags:** `userPresence | privateKeyUsage`

The most permissive biometric trait. The system first attempts biometric authentication (Face ID or Touch ID); if that fails or is unavailable, it falls back to the device passcode.

**Credential parameter:** `laContext: LAContext?` — same as `BiometryAnyProtectedKey`.

**`KeyManagementActor` isolation:** Yes.

**Simulator support:** Yes, with limitations — the operation compiles and succeeds on the simulator, but no biometric or passcode check is performed. The `laContext` credential is ignored by `SoftwareKeyStore` and the private-key operation always succeeds silently. Run integration tests on a real device to verify actual user-presence authentication.

```swift
struct UserPresenceKey: UserPresenceProtectedKey {
    let name = "com.example.app.presence"
}

let signature = try await manager.sign(payload: data, with: UserPresenceKey(), laContext: nil)
```

---

## `UnprotectedKey`

**Access control flags:** `privateKeyUsage` only — no access control.

The private key is backed by the Secure Enclave but requires no user authentication. Any call to a private-key operation succeeds without prompting. This is useful for operations that prove *device possession* (the Secure Enclave hardware is present) without requiring the user to authenticate.

**Credential parameter:** None.

**`KeyManagementActor` isolation:** No.

**Simulator support:** Yes — `SoftwareKeyStore` emulates `UnprotectedKey` on the simulator using software P-256 keys. No access control is enforced in the emulated store.

> **Warning:** Any code that can reach the device can perform private-key operations. Use this trait only when device possession alone is a sufficient security guarantee for your use case.

```swift
struct DeviceKey: UnprotectedKey {
    let name = "com.example.app.device"
}

let signature = try manager.sign(payload: data, with: DeviceKey())
```

---

## Choosing the right trait

| Question                                                   | Recommendation                   |
| ---------------------------------------------------------- | -------------------------------- |
| Can the user tolerate entering a password in your UI?      | `PasswordProtectedKey`           |
| Should the system handle auth with Face ID / Touch ID?     | `BiometryAnyProtectedKey`        |
| Should the key be invalidated when biometrics change?      | `BiometryCurrentSetProtectedKey` |
| Should the system handle auth with the device passcode?    | `PasscodeProtectedKey`           |
| Should biometry be attempted first with passcode fallback? | `UserPresenceProtectedKey`       |
| Is device possession alone a sufficient guarantee?         | `UnprotectedKey`                 |

---

## Configuration mismatch

When a key is first auto-created, the manager persists both its **trait** and its **`protectionMode`**. If you later call an operation with either a different trait *or* a different `protectionMode` for the same key name, the manager throws `configurationMismatch`. The fix is to either:

- Use a different `name` for the new trait, or
- Remove the existing key and let the manager re-create it with the new trait.

```swift
struct MyPasswordKey:    PasswordProtectedKey  { let name = "myKey" }
struct MyUnprotectedKey: UnprotectedKey        { let name = "myKey" }

// First use creates the key with the PasswordProtectedKey trait
_ = try manager.sign(payload: data, with: MyPasswordKey(), password: password)

// This throws configurationMismatch — same name, but different trait
_ = try manager.sign(payload: data, with: MyUnprotectedKey())
```
