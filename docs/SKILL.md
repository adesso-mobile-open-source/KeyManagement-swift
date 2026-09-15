---
description: >
  Hardware-backed P-256 key management for iOS. Stores private keys in the
  Secure Enclave (real device) or a software store (simulator). Exposes signing,
  ECDH key agreement, and ECIES encrypt/decrypt. All operations are typed-throw,
  synchronous, and Sendable.
when_to_use: >
  Load this skill whenever you are writing, reviewing, or debugging code that
  imports KeyManagement — key creation, signing, encryption, decryption, or key
  descriptor definitions.
---

# KeyManagement — API Reference for AI Agents

---

## Core concepts

### KeyManagerImpl — production entry point

```swift
let manager = KeyManagerImpl(applicationTag: "com.example.app")
```

- Create **once** per `applicationTag`; keep alive for the feature lifetime.
- Inject as `any KeyManager` in production; substitute a spy in tests.
- `applicationTag` + `key.name` form the keychain tag. Changing either makes existing keys invisible.

### Key descriptor

A plain `struct` conforming to one of the six trait protocols. Carries no secrets.

```swift
struct MyKey: PasswordProtectedKey {
    let name = "com.example.signing"           // stable, namespaced string
    let protectionMode: ProtectionMode = .whenUnlockedThisDeviceOnly  // default
}
```

Both properties have defaults: `name` = type name (unsafe for production — always override), `protectionMode` = `.whenUnlockedThisDeviceOnly`.

### Trait protocols

| Protocol | Auth required | `BiometryActor` | Notes |
|---|---|---|---|
| `PasswordProtectedKey` | `password: Data` | No | Simulator: fully emulated |
| `BiometryAnyProtectedKey` | `laContext: LAContext?` | Yes | Simulator: succeeds silently |
| `BiometryCurrentSetProtectedKey` | `laContext: LAContext?` | Yes | Invalidated on enrollment change; monitor with `hasBiometricEnrollmentChanged` |
| `PasscodeProtectedKey` | system passcode UI | No | Simulator: succeeds silently |
| `UserPresenceProtectedKey` | `laContext: LAContext?` | Yes | Biometry OR passcode |
| `UnprotectedKey` | none | No | |

`BiometryActor` is a dedicated global actor (not `MainActor`) that isolates the blocking, biometry-gated Secure Enclave calls off the main thread. `Yes` rows must be called with `await`.

### @KeyName macro — parameterised names

```swift
@KeyName("account.{accountId}.signing")
struct AccountKey: PasswordProtectedKey {}

let key = AccountKey(accountId: "user-42")  // key.name == "account.user-42.signing"
```

### ProtectionMode

```
.whenUnlockedThisDeviceOnly   // default — device-bound, requires unlock
.whenUnlocked                 // same but migrates via backup
.afterFirstUnlockThisDeviceOnly // background-accessible, device-bound
.afterFirstUnlock             // background-accessible, migrates
.whenPasscodeSetThisDeviceOnly  // deleted if passcode removed, never migrates
```

---

## Auto-creation rules

| Operation | Auto-creates? |
|---|---|
| `sign`, `deriveSharedSecret`, `decrypt` | **Yes** — on first call |
| `create(key:)` | Explicit; throws `keyAlreadyExists` if present |
| `hasKey`, `getPublicKey` | **No** — throws if absent |
| `encrypt(data:with:)` — non-password traits | **Yes** — auto-creates on first call |
| `encrypt(data:with:)` — `PasswordProtectedKey` | **No** — throws `keyNotFound` if absent |
| `encrypt(data:with:generateKeyWithPassword:)` | **Yes** — `PasswordProtectedKey` only |

---

## KeyManager protocol — method signatures

### Trait-agnostic

```swift
func hasKey<K: KeyDescriptor>(_ key: K) throws(HasKeyError) -> Bool
func getPublicKey<K: KeyDescriptor>(_ key: K) throws(GetPublicKeyError) -> Data
func encrypt<K: KeyDescriptor>(data: Data, with key: K) throws(EncryptError) -> Data
func removeKey<K: KeyDescriptor>(_ key: K) throws(RemoveKeyError)
func removeKey<K: BiometryCurrentSetProtectedKey>(_ key: K) throws(RemoveKeyError)  // also clears enrollment baseline
func hasBiometricEnrollmentChanged<K: BiometryCurrentSetProtectedKey>(for key: K) throws(EnrollmentCheckError) -> Bool
```

### PasswordProtectedKey

```swift
func create<K: PasswordProtectedKey>(key: K, password: Data) throws(CreateKeyError) -> Data
func encrypt<K: PasswordProtectedKey>(data: Data, with key: K, generateKeyWithPassword password: Data) throws(EncryptError) -> Data
func sign<K: PasswordProtectedKey>(payload: Data, with key: K, password: Data) throws(SignPasswordError) -> Data
func deriveSharedSecret<K: PasswordProtectedKey>(with key: K, publicKey: Data, password: Data) throws(DerivePasswordError) -> Data
func decrypt<K: PasswordProtectedKey>(encodedData: Data, with key: K, password: Data) throws(DecryptPasswordError) -> Data
```

### BiometryAnyProtectedKey (`@BiometryActor` for create/sign/derive/decrypt)

```swift
func create<K: BiometryAnyProtectedKey>(key: K) throws(CreateKeyError) -> Data           // @BiometryActor
func encrypt<K: BiometryAnyProtectedKey>(data: Data, with key: K) throws(EncryptError) -> Data  // auto-creates
func sign<K: BiometryAnyProtectedKey>(payload: Data, with key: K, laContext: LAContext?) throws(SignBiometryAnyError) -> Data  // @BiometryActor
func deriveSharedSecret<K: BiometryAnyProtectedKey>(with key: K, publicKey: Data, laContext: LAContext?) throws(DeriveBiometryAnyError) -> Data  // @BiometryActor
func decrypt<K: BiometryAnyProtectedKey>(encodedData: Data, with key: K, laContext: LAContext?) throws(DecryptBiometryAnyError) -> Data  // @BiometryActor
```

### BiometryCurrentSetProtectedKey (`@BiometryActor` for create/sign/derive/decrypt)

```swift
func create<K: BiometryCurrentSetProtectedKey>(key: K) throws(CreateKeyError) -> Data    // @BiometryActor
func encrypt<K: BiometryCurrentSetProtectedKey>(data: Data, with key: K) throws(EncryptError) -> Data  // auto-creates
func sign<K: BiometryCurrentSetProtectedKey>(payload: Data, with key: K, laContext: LAContext?) throws(SignBiometryCurrentSetError) -> Data  // @BiometryActor
func deriveSharedSecret<K: BiometryCurrentSetProtectedKey>(with key: K, publicKey: Data, laContext: LAContext?) throws(DeriveBiometryCurrentSetError) -> Data  // @BiometryActor
func decrypt<K: BiometryCurrentSetProtectedKey>(encodedData: Data, with key: K, laContext: LAContext?) throws(DecryptBiometryCurrentSetError) -> Data  // @BiometryActor
```

### PasscodeProtectedKey

```swift
func create<K: PasscodeProtectedKey>(key: K) throws(CreateKeyError) -> Data
func encrypt<K: PasscodeProtectedKey>(data: Data, with key: K) throws(EncryptError) -> Data  // auto-creates
func sign<K: PasscodeProtectedKey>(payload: Data, with key: K) throws(SignPasscodeError) -> Data
func deriveSharedSecret<K: PasscodeProtectedKey>(with key: K, publicKey: Data) throws(DerivePasscodeError) -> Data
func decrypt<K: PasscodeProtectedKey>(encodedData: Data, with key: K) throws(DecryptPasscodeError) -> Data
```

### UserPresenceProtectedKey (`@BiometryActor` for create/sign/derive/decrypt)

```swift
func create<K: UserPresenceProtectedKey>(key: K) throws(CreateKeyError) -> Data           // @BiometryActor
func encrypt<K: UserPresenceProtectedKey>(data: Data, with key: K) throws(EncryptError) -> Data  // auto-creates
func sign<K: UserPresenceProtectedKey>(payload: Data, with key: K, laContext: LAContext?) throws(SignUserPresenceError) -> Data  // @BiometryActor
func deriveSharedSecret<K: UserPresenceProtectedKey>(with key: K, publicKey: Data, laContext: LAContext?) throws(DeriveUserPresenceError) -> Data  // @BiometryActor
func decrypt<K: UserPresenceProtectedKey>(encodedData: Data, with key: K, laContext: LAContext?) throws(DecryptUserPresenceError) -> Data  // @BiometryActor
```

### UnprotectedKey

```swift
func create<K: UnprotectedKey>(key: K) throws(CreateKeyError) -> Data
func encrypt<K: UnprotectedKey>(data: Data, with key: K) throws(EncryptError) -> Data    // auto-creates
func sign<K: UnprotectedKey>(payload: Data, with key: K) throws(SignUnprotectedError) -> Data
func deriveSharedSecret<K: UnprotectedKey>(with key: K, publicKey: Data) throws(DeriveUnprotectedError) -> Data
func decrypt<K: UnprotectedKey>(encodedData: Data, with key: K) throws(DecryptUnprotectedError) -> Data
```

---

## Error types

### CreateKeyError
```
.keyAlreadyExists(name:)       // call removeKey first or check hasKey
.creationFailed(name:, error:)
.configurationMismatch(name:)
```

### EncryptError
```
.keyNotFound(name:)            // key doesn't exist; use a write op or generateKeyWithPassword
.retrievalFailed(name:, error:)
.encryptionFailed(name:, error:)
.keyCreationFailed(error:)     // generateKeyWithPassword overload only
```

### HasKeyError / GetPublicKeyError / RemoveKeyError / EnrollmentCheckError
```
HasKeyError:         .lookupFailed(name:, error:)
GetPublicKeyError:   .keyNotFound(name:) | .retrievalFailed(name:, error:)
RemoveKeyError:      .removalFailed(name:, status: OSStatus)
EnrollmentCheckError: .lookupFailed(error:)
```

### Sign / Derive / Decrypt error cases by trait

All six traits share this common set (where applicable):

| Case | Password | BiometryAny | BiometryCurrentSet | Passcode | UserPresence | Unprotected |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `configurationMismatch(name:)` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `keyCreationFailed(error:)` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `signingFailed` / `derivationFailed` / `decryptionFailed` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `invalidPassword(name:)` | ✓ | | | | | |
| `userCancelled(name:)` | | ✓ | ✓ | | ✓ | |
| `biometryLockout(name:)` | | ✓ | ✓ | | ✓ | |
| `enrollmentChanged(name:)` | | | ✓ | | | |
| `invalidPayload` (decrypt only) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Key rules an AI must follow

1. **Never store a password in a key descriptor.** Passwords are call-site parameters only.
2. **Always override `name` with a stable string literal.** The default (type name) breaks if the struct is renamed.
3. **`BiometryActor`-isolated traits** (`BiometryAny`, `BiometryCurrentSet`, `UserPresence`): all `create`, `sign`, `deriveSharedSecret`, `decrypt` calls are isolated to `BiometryActor` — a dedicated background actor, never the main actor. Call them with `await`.
4. **`BiometryCurrentSetProtectedKey`**: call `hasBiometricEnrollmentChanged(for:)` before private-key operations; if `true`, remove the key and guide the user to re-register.
5. **Auto-create on first call** applies to `sign`, `deriveSharedSecret`, `decrypt`, and `encrypt` (non-password traits). If the key is brand-new, any ciphertext encrypted before the key existed cannot be decrypted — it will fail with `decryptionFailed`. For `PasswordProtectedKey`, use `encrypt(generateKeyWithPassword:)` or `create` + `encrypt` to control when the key is created.
6. **`encrypt` ciphertext** requires `> 81` bytes to be valid; shorter inputs throw `invalidPayload` on decrypt.
7. **`publicKey` for `deriveSharedSecret`** must be x963-encoded (uncompressed, 65 bytes). `getPublicKey` returns DER (91 bytes) — convert before passing to derive.
8. **`configurationMismatch`**: the key exists under a different trait. Call `removeKey` then let auto-create run with the new trait.
9. **Simulator**: `PasswordProtectedKey` and `UnprotectedKey` are fully emulated. All other traits compile and succeed but skip auth entirely — do not rely on simulator results for security correctness.
