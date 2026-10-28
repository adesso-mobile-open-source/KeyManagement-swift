# Encrypt / Decrypt

KeyManagement provides ECIES (Elliptic Curve Integrated Encryption Scheme) encryption and decryption using Apple's `eciesEncryptionCofactorX963SHA256AESGCM` algorithm.

## How it works

- **Encrypt** uses only the key's *public* key — no authentication required, no biometric prompt.
- **Decrypt** uses the *private* key inside the Secure Enclave — authentication is required, matching the trait of the key.

The ciphertext produced by `encrypt` is an opaque byte sequence (ECIES format). It is only decryptable using the corresponding private key through `decrypt`. The format is compatible with Apple's Security framework and CryptoKit's ECIES implementation.

## Encrypt

`encrypt(data:with:)` uses only the public key — no authentication is required regardless of the key's trait. For all traits except `PasswordProtectedKey`, it **auto-creates** the key pair on first call. For `PasswordProtectedKey`, a dedicated overload is required.

### Non-password traits — auto-creating

```swift
struct EncryptionKey: BiometryAnyProtectedKey {
    let name = "com.example.app.encryption"
}

let plaintext = Data("sensitive data".utf8)

// Auto-creates the key on first call, then encrypts — no auth needed
let ciphertext = try manager.encrypt(data: plaintext, with: EncryptionKey())
```

The same applies to `BiometryCurrentSetProtectedKey`, `PasscodeProtectedKey`, `UserPresenceProtectedKey`, and `UnprotectedKey`.

### PasswordProtectedKey — plain overload does not auto-create

For `PasswordProtectedKey`, the plain `encrypt(data:with:)` overload requires the key to already exist. Use `create` first, or use the dedicated `generateKeyWithPassword` overload:

```swift
struct PasswordEncKey: PasswordProtectedKey {
    let name = "com.example.app.encryption"
}

let password = Data("my-password".utf8)
let plaintext = Data("sensitive data".utf8)

// Option A: ensure the key exists first
_ = try manager.create(key: PasswordEncKey(), password: password)
let ciphertext = try manager.encrypt(data: plaintext, with: PasswordEncKey())

// Option B: auto-creating overload
let ciphertext = try manager.encrypt(
    data: plaintext,
    with: PasswordEncKey(),
    generateKeyWithPassword: password
)
```

## Explicit key creation

Use `create(key:)` (or `create(key:password:)` for password-protected keys) when you need the public key immediately — typically to register it with a server — without having to perform a sign or decrypt round-trip first.

`create` returns the DER-encoded P-256 public key and throws `CreateKeyError.keyAlreadyExists` if the key is already present.

```swift
struct RegistrationKey: PasswordProtectedKey {
    let name = "com.example.app.registration"
}

let password = Data("my-password".utf8)
let manager  = KeyManagerImpl(applicationTag: "com.example.app")

// Create the key and get the public key in one step
let publicKeyDER = try manager.create(key: RegistrationKey(), password: password)

// Register publicKeyDER with your server...

// Later: encrypt data — key already exists, use the plain overload
let ciphertext = try manager.encrypt(data: plaintext, with: RegistrationKey())
```

For non-password traits the `password` parameter is omitted:

```swift
struct BiometricRegKey: BiometryAnyProtectedKey {
    let name = "com.example.app.biometric"
}

// Isolated to KeyManagementActor — await it directly, no manual actor hop needed
let publicKeyDER = try await manager.create(key: BiometricRegKey())
```

## Decrypt

`decrypt` requires the credential matching the key's trait, because it accesses the private key.

### Password-protected key

```swift
let recovered = try manager.decrypt(
    encodedData: ciphertext,
    with: EncryptionKey(),
    password: password
)
assert(recovered == plaintext)
```

### Biometry key (`KeyManagementActor`)

```swift
struct BiometricEncKey: BiometryAnyProtectedKey {
    let name = "com.example.app.biometricenc"
}

// Biometric prompt shown automatically. `decrypt` is isolated to
// KeyManagementActor, so it must be awaited.
let recovered = try await manager.decrypt(
    encodedData: ciphertext,
    with: BiometricEncKey(),
    laContext: nil
)
```

### Passcode key (`KeyManagementActor`)

```swift
struct PasscodeEncKey: PasscodeProtectedKey {
    let name = "com.example.app.passcodeenc"
}

// System shows passcode UI, which blocks the calling thread exactly like a
// biometric prompt. `decrypt` is isolated to KeyManagementActor, so it must
// be awaited.
let recovered = try await manager.decrypt(
    encodedData: ciphertext,
    with: PasscodeEncKey()
)
```

### Unprotected key

```swift
struct DeviceEncKey: UnprotectedKey {
    let name = "com.example.app.deviceenc"
}

let recovered = try manager.decrypt(
    encodedData: ciphertext,
    with: DeviceEncKey()
)
```

## Error handling

| Error case                             | Cause                                                                                                                                                                                                                               |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EncryptError.keyNotFound`             | `encrypt(data:with:)` called on a `PasswordProtectedKey` before the key exists. Use `create` first, or use the `generateKeyWithPassword` overload.                                                                                  |
| `EncryptError.keyCreationFailed`       | Auto-create during `encrypt` failed (all non-password traits, or the `generateKeyWithPassword` overload).                                                                                                                           |
| `CreateKeyError.keyAlreadyExists`      | `create` was called but a key with that name already exists.                                                                                                                                                                        |
| `CreateKeyError.creationFailed`        | Key-pair generation in the Secure Enclave failed.                                                                                                                                                                                   |
| `CreateKeyError.configurationMismatch` | A configuration record exists for this name with a different trait.                                                                                                                                                                 |
| `.invalidPayload`                      | `encodedData` is 81 bytes or shorter — too short to be a valid ECIES payload.                                                                                                                                                       |
| `.invalidPassword`                     | Wrong password supplied (PasswordProtectedKey only).                                                                                                                                                                                |
| `.userCancelled`                       | User dismissed the biometric prompt.                                                                                                                                                                                                |
| `.biometryLockout`                     | Too many failed biometric attempts.                                                                                                                                                                                                 |
| `.enrollmentChanged`                   | Biometrics have changed (BiometryCurrentSetProtectedKey only).                                                                                                                                                                      |
| `.decryptionFailed`                    | The ciphertext could not be decrypted — typically because it was not produced by `encrypt` for the same key, or the key was rotated.                                                                                                |
| `.configurationMismatch`               | The key exists but was created with a different trait.                                                                                                                                                                              |
| `.keyCreationFailed`                   | Auto-create failed during `decrypt` (only if the key did not yet exist). Note: if `decrypt` auto-creates a new key, the provided `encodedData` was encrypted for a different key and decryption will fail with `.decryptionFailed`. |

## Ciphertext format

The ciphertext is produced by `SecKeyCreateEncryptedData` using `.eciesEncryptionCofactorX963SHA256AESGCM`. It is an opaque blob — do not attempt to parse or construct it manually. Its minimum length is 82 bytes (65-byte uncompressed ephemeral public key + 16-byte AES-GCM tag + at least 1 byte of ciphertext); shorter inputs are rejected with `.invalidPayload`.

## Typical roundtrips

### Create, then encrypt

```swift
struct DataKey: PasswordProtectedKey {
    let name = "com.example.data.key"
}

let password = Data("secret".utf8)
let manager  = KeyManagerImpl(applicationTag: "com.example.app")

// Step 1: ensure the key exists
_ = try manager.create(key: DataKey(), password: password)

// Step 2: encrypt
let plaintext  = Data("my sensitive payload".utf8)
let ciphertext = try manager.encrypt(data: plaintext, with: DataKey())

// Step 3: decrypt (requires the correct password)
let recovered  = try manager.decrypt(encodedData: ciphertext, with: DataKey(), password: password)
assert(recovered == plaintext)
```

### Create for registration, then encrypt

```swift
struct RegKey: PasswordProtectedKey {
    let name = "com.example.reg.key"
}

let password = Data("secret".utf8)

// Step 1: create and register the public key
let publicKeyDER = try manager.create(key: RegKey(), password: password)
// upload publicKeyDER to server...

// Step 2: encrypt locally
let ciphertext = try manager.encrypt(data: plaintext, with: RegKey())

// Step 3: decrypt
let recovered = try manager.decrypt(encodedData: ciphertext, with: RegKey(), password: password)
```
