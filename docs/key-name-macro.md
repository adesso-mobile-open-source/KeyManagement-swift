# `@KeyName` Macro

The `@KeyName` macro generates a parameterised `name` property for a key descriptor struct. Use it when the key name must embed one or more runtime values — for example, a user ID, account ID, or tenant ID.

## Basic usage

```swift
import KeyManagement

@KeyName("account/{accountId}/signing")
struct AccountSigningKey: PasswordProtectedKey {}
```

The macro expands this to:

```swift
struct AccountSigningKey: PasswordProtectedKey {
    public let accountId: any KeyNameParameterStringConvertible
    public var name: String { "account/\(accountId.stringRepresentation)/signing" }
}
```

You then initialise the struct with a concrete parameter value:

```swift
let key = AccountSigningKey(accountId: "user-42")
// key.name == "account/user-42/signing"

let signature = try manager.sign(payload: data, with: key, password: password)
```

## Multiple parameters

You can use as many `{placeholder}` segments as needed:

```swift
@KeyName("{tenantId}/{userId}/encryption")
struct TenantUserEncryptionKey: BiometryAnyProtectedKey {}

let key = TenantUserEncryptionKey(tenantId: "acme", userId: "bob")
// key.name == "acme/bob/encryption"
```

## Static name (no parameters)

A template with no placeholders generates only the `name` property:

```swift
@KeyName("global/device/attestation")
struct DeviceAttestationKey: UnprotectedKey {}

// DeviceAttestationKey() has no initialiser parameters
let key = DeviceAttestationKey()
// key.name == "global/device/attestation"
```

This is equivalent to writing `let name = "global/device/attestation"` by hand, but is explicit about the naming scheme.

## `KeyNameParameterStringConvertible`

Generated stored properties are typed `any KeyNameParameterStringConvertible`. The library provides conformances for the most common types out of the box:

| Type                          | `stringRepresentation`                |
| ----------------------------- | ------------------------------------- |
| `String`                      | The string value itself               |
| `Int`                         | The decimal string representation     |
| `UUID`                        | `uuidString` (upper-case, hyphenated) |
| Any `CustomStringConvertible` | `description`                         |

To use a custom type, conform it to `KeyNameParameterStringConvertible`:

```swift
struct UserID: KeyNameParameterStringConvertible {
    let value: Int
    var stringRepresentation: String { "user-\(value)" }
}

@KeyName("account/{userId}/key")
struct AccountKey: PasswordProtectedKey {}

let key = AccountKey(userId: UserID(value: 42))
// key.name == "account/user-42/key"
```

## Compile-time validation

The macro validates your template at compile time and emits a diagnostic if:

- The template is empty or contains only whitespace.
- A placeholder name is not a valid Swift identifier (e.g. `{123bad}` or `{my-param}`).
- The same placeholder name appears more than once.

```swift
@KeyName("")                   // error: @KeyName template must not be empty.
@KeyName("{123bad}")           // error: @KeyName placeholder '123bad' is not a valid Swift identifier.
@KeyName("{id}/foo/{id}")      // error: @KeyName template contains duplicate placeholder names.
```

## Key uniqueness warning

Each unique combination of parameter values produces a distinct key name and therefore a distinct key in the keychain. There is no automatic garbage-collection of keys for old parameter values. If your parameter space is unbounded (e.g. sequential integers), ensure you call `removeKey(_:)` when a key is no longer needed.

```swift
// Key for user 1
try manager.removeKey(AccountSigningKey(accountId: "user-1"))

// Key for user 2 is unaffected
let sig = try manager.sign(payload: data, with: AccountSigningKey(accountId: "user-2"), password: pw)
```
