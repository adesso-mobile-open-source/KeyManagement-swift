//
//  KeyManager.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 06.07.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import Foundation
import LocalAuthentication

/// The public contract for hardware-backed cryptographic key management.
///
/// `KeyManager` is the single entry point for all key operations. Declare
/// dependencies against `any KeyManager` so that unit tests can substitute a
/// spy or stub without touching the Secure Enclave or the keychain.
///
/// ```swift
/// class AuthService {
///     private let keyManager: any KeyManager
///     init(keyManager: any KeyManager = KeyManagerImpl(applicationTag: "com.example.app")) {
///         self.keyManager = keyManager
///     }
/// }
/// ```
///
/// The production implementation is ``KeyManagerImpl``. Create it once per
/// `applicationTag` and keep it alive for the lifetime of the feature.
///
/// ## Write operations auto-create
///
/// `sign`, `deriveSharedSecret`, and `decrypt` create the key pair in the
/// Secure Enclave automatically on their first call if the key does not yet
/// exist.
///
/// ## Explicit creation
///
/// Call `create(key:)` (or `create(key:password:)` for password-protected keys)
/// when you need the public key immediately — for example, to register it with a
/// server before performing any signing. `create` returns the DER-encoded public
/// key and throws ``CreateKeyError/keyAlreadyExists(name:)`` if the key is
/// already present.
///
    /// ## Read-only operations do not auto-create
    ///
    /// `hasKey` and `getPublicKey` never create a key. `encrypt` auto-creates for
    /// all traits except `PasswordProtectedKey` — use
    /// ``encrypt(data:with:generateKeyWithPassword:)`` to auto-create a
    /// password-protected key on first call.
///
/// ## Configuration mismatch
///
/// Each key has its trait persisted alongside its name. If you call an
/// operation with a different trait than was used when the key was created,
/// the manager throws `configurationMismatch`. Remove the existing key and
/// let the auto-create path recreate it with the new trait.
public protocol KeyManager: KeyManagerPasscodeOperations, KeyManagerUnprotectedOperations, Sendable {

    // MARK: - Read-only (trait-agnostic)

    /// Returns whether a key with the given descriptor exists in the keystore.
    ///
    /// This method does **not** auto-create the key.
    ///
    /// - Parameter key: A key descriptor whose ``KeyDescriptor/name`` is used
    ///   to look up the key.
    /// - Returns: `true` if the key exists; `false` if it does not.
    /// - Throws: ``HasKeyError/lookupFailed(name:error:)`` if the keychain
    ///   query itself fails unexpectedly.
    func hasKey<K: KeyDescriptor>(_ key: K) throws(HasKeyError) -> Bool

    /// Returns the DER-encoded P-256 public key for the given key descriptor.
    ///
    /// This method does **not** auto-create the key. Call any write operation
    /// first to ensure the key exists.
    ///
    /// The returned `Data` is a DER-encoded `SubjectPublicKeyInfo` structure for
    /// a P-256 key (91 bytes). It can be passed to
    /// `P256.Signing.PublicKey(derRepresentation:)` for signature verification,
    /// or shared with a server for key agreement.
    ///
    /// - Parameter key: A key descriptor identifying the key to retrieve.
    /// - Returns: DER-encoded P-256 public key data.
    /// - Throws: ``GetPublicKeyError``
    func getPublicKey<K: KeyDescriptor>(_ key: K) throws(GetPublicKeyError) -> Data

    // MARK: - removeKey

    /// Removes the key and its configuration record from the keystore.
    ///
    /// Removal is idempotent — if the key does not exist, this method returns
    /// without error.
    ///
    /// Use the ``BiometryCurrentSetProtectedKey`` overload for current-set keys
    /// to also clear the biometric enrollment baseline.
    ///
    /// - Parameter key: A descriptor identifying the key to remove.
    /// - Throws: ``RemoveKeyError/removalFailed(name:status:)`` if the keychain
    ///   delete operation fails.
    func removeKey<K: KeyDescriptor>(_ key: K) throws(RemoveKeyError)

    /// Removes a ``BiometryCurrentSetProtectedKey`` key and clears its biometric
    /// enrollment baseline.
    ///
    /// After calling this method, ``hasBiometricEnrollmentChanged(for:)`` returns
    /// `true` until the key is recreated by a write operation.
    ///
    /// - Parameter key: A descriptor identifying the current-set key to remove.
    /// - Throws: ``RemoveKeyError/removalFailed(name:status:)`` if the keychain
    ///   delete operation fails.
    func removeKey<K: BiometryCurrentSetProtectedKey>(_ key: K) throws(RemoveKeyError)

    // MARK: - Enrollment

    /// Checks whether the device's biometric enrollment has changed since the
    /// key was last created.
    ///
    /// This method is **synchronous and prompt-free** — it compares the current
    /// `LAContext.evaluatedPolicyDomainState` against the baseline stored when
    /// the key was auto-created, without showing any system UI.
    ///
    /// Call this method before any private-key operation on a
    /// ``BiometryCurrentSetProtectedKey`` key to detect hardware invalidation
    /// early and guide the user through re-enrolment.
    ///
    /// Returns `true` when:
    /// - The enrolled biometrics have changed since the key was created.
    /// - No baseline exists (key was never created, or was removed).
    ///
    /// Returns `false` only when the enrollment is confirmed unchanged.
    ///
    /// - Parameter key: A descriptor identifying the current-set key to check.
    /// - Returns: `true` if the enrollment has changed or no baseline exists;
    ///   `false` if enrollment is unchanged.
    /// - Throws: ``EnrollmentCheckError/lookupFailed(error:)`` if the storage
    ///   read fails unexpectedly.
    func hasBiometricEnrollmentChanged<K: BiometryCurrentSetProtectedKey>(for key: K) throws(EnrollmentCheckError)
        -> Bool

    // MARK: - PasswordProtectedKey

    /// Explicitly creates the key pair for a ``PasswordProtectedKey`` and returns
    /// the DER-encoded public key.
    ///
    /// Use this when you need the public key immediately after creation — for
    /// example, to register it with a backend — without first performing a sign
    /// or decrypt operation. Auto-creation via `sign`/`decrypt` still works
    /// independently; calling `create` first is purely optional.
    ///
    /// - Parameters:
    ///   - key: A descriptor identifying the key to create.
    ///   - password: The application password to protect the private key.
    /// - Returns: DER-encoded P-256 public key data (91 bytes).
    /// - Throws: ``CreateKeyError``
    func create<K: PasswordProtectedKey>(key: K, password: Data) throws(CreateKeyError) -> Data

    /// Encrypts `data` using the public key of a ``PasswordProtectedKey``.
    ///
    /// Unlike the plain `encrypt(data:with:)` overload for every other trait,
    /// this overload does **not** auto-create the key — a
    /// ``PasswordProtectedKey`` cannot be created without a password. Call
    /// `sign`, `deriveSharedSecret`, `decrypt`, or `create` first to ensure the
    /// key exists, or use
    /// ``encrypt(data:with:generateKeyWithPassword:)`` to auto-create it.
    ///
    /// - Parameters:
    ///   - data: The plaintext bytes to encrypt.
    ///   - key: A descriptor identifying which key's public key to use.
    /// - Returns: ECIES ciphertext (minimum 82 bytes).
    /// - Throws: ``EncryptError/keyNotFound(name:)`` if the key does not yet
    ///   exist; ``EncryptError/encryptionFailed(name:error:)`` if encryption
    ///   fails.
    func encrypt<K: PasswordProtectedKey>(data: Data, with key: K) throws(EncryptError) -> Data

    /// Encrypts `data` using the public key of a ``PasswordProtectedKey``,
    /// auto-creating the key if it does not yet exist.
    ///
    /// This overload behaves identically to the plain ``encrypt(data:with:)``
    /// overload except that it creates the key pair on first call using the
    /// supplied `password`. Subsequent calls with the same key skip creation.
    ///
    /// - Parameters:
    ///   - data: The plaintext bytes to encrypt.
    ///   - key: A descriptor identifying which key's public key to use.
    ///   - password: The application password used to create the key if absent.
    /// - Returns: ECIES ciphertext (minimum 82 bytes).
    /// - Throws: ``EncryptError``
    func encrypt<K: PasswordProtectedKey>(data: Data, with key: K, generateKeyWithPassword password: Data)
        throws(EncryptError) -> Data

    /// Signs `payload` using a ``PasswordProtectedKey`` and returns a DER-encoded
    /// ECDSA signature.
    ///
    /// Auto-creates the key in the Secure Enclave on first call.
    ///
    /// - Parameters:
    ///   - payload: The data to sign. The Secure Enclave applies SHA-256
    ///     internally before signing.
    ///   - key: A descriptor identifying the signing key.
    ///   - password: The application password associated with this key.
    /// - Returns: DER-encoded P-256 ECDSA signature.
    /// - Throws: ``SignPasswordError``
    func sign<K: PasswordProtectedKey>(payload: Data, with key: K, password: Data) throws(SignPasswordError) -> Data

    /// Performs ECDH key agreement using a ``PasswordProtectedKey`` and returns
    /// the 32-byte raw shared secret.
    ///
    /// Auto-creates the key in the Secure Enclave on first call. The ephemeral
    /// public key should be an x963-encoded (uncompressed, 65-byte) P-256 key
    /// from the other party.
    ///
    /// - Parameters:
    ///   - key: A descriptor identifying the key to use.
    ///   - publicKey: The other party's x963-encoded P-256 public key.
    ///   - password: The application password associated with this key.
    /// - Returns: 32-byte raw ECDH shared secret (Z value).
    /// - Throws: ``DerivePasswordError``
    func deriveSharedSecret<K: PasswordProtectedKey>(with key: K, publicKey: Data, password: Data)
        throws(DerivePasswordError) -> Data

    /// Decrypts ECIES-encoded data using a ``PasswordProtectedKey``.
    ///
    /// Auto-creates the key in the Secure Enclave on first call. The
    /// `encodedData` must have been produced by ``encrypt(data:with:)`` using
    /// the same key.
    ///
    /// - Parameters:
    ///   - encodedData: ECIES ciphertext. Must be more than 81 bytes.
    ///   - key: A descriptor identifying the key to use.
    ///   - password: The application password associated with this key.
    /// - Returns: Decrypted plaintext.
    /// - Throws: ``DecryptPasswordError``
    func decrypt<K: PasswordProtectedKey>(encodedData: Data, with key: K, password: Data) throws(DecryptPasswordError)
        -> Data

    // MARK: - BiometryAnyProtectedKey

    /// Explicitly creates the key pair for a ``BiometryAnyProtectedKey`` and
    /// returns the DER-encoded public key. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// Use this when you need the public key immediately — for example, to
    /// register it with a backend — before performing any signing or decryption.
    ///
    /// - Parameter key: A descriptor identifying the key to create.
    /// - Returns: DER-encoded P-256 public key data (91 bytes).
    /// - Throws: ``CreateKeyError``
    @BiometryActor func create<K: BiometryAnyProtectedKey>(key: K) throws(CreateKeyError) -> Data

    /// Encrypts `data` using the public key of a ``BiometryAnyProtectedKey``,
    /// auto-creating the key if it does not yet exist. No authentication required.
    /// - Throws: ``EncryptError``
    func encrypt<K: BiometryAnyProtectedKey>(data: Data, with key: K) throws(EncryptError) -> Data

    /// Signs `payload` using a ``BiometryAnyProtectedKey`` after biometric
    /// authentication. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// Pass `nil` for `laContext` to let the system show a biometric prompt.
    /// Pass a pre-evaluated context to avoid a second prompt.
    ///
    /// - Throws: ``SignBiometryAnyError``
    @BiometryActor func sign<K: BiometryAnyProtectedKey>(payload: Data, with key: K, laContext: LAContext?)
        throws(SignBiometryAnyError) -> Data

    /// Performs ECDH key agreement using a ``BiometryAnyProtectedKey`` after
    /// biometric authentication. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// `publicKey` must be an x963-encoded (uncompressed, 65-byte) P-256 key.
    /// - Throws: ``DeriveBiometryAnyError``
    @BiometryActor func deriveSharedSecret<K: BiometryAnyProtectedKey>(
        with key: K,
        publicKey: Data,
        laContext: LAContext?
    ) throws(DeriveBiometryAnyError) -> Data

    /// Decrypts ECIES data using a ``BiometryAnyProtectedKey`` after biometric
    /// authentication. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// - Throws: ``DecryptBiometryAnyError``
    @BiometryActor func decrypt<K: BiometryAnyProtectedKey>(encodedData: Data, with key: K, laContext: LAContext?)
        throws(DecryptBiometryAnyError) -> Data

    // MARK: - BiometryCurrentSetProtectedKey

    /// Explicitly creates the key pair for a ``BiometryCurrentSetProtectedKey``
    /// and returns the DER-encoded public key. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// Also stores the current biometric enrollment baseline so that
    /// ``hasBiometricEnrollmentChanged(for:)`` can detect future enrollment
    /// changes correctly.
    ///
    /// - Parameter key: A descriptor identifying the key to create.
    /// - Returns: DER-encoded P-256 public key data (91 bytes).
    /// - Throws: ``CreateKeyError``
    @BiometryActor func create<K: BiometryCurrentSetProtectedKey>(key: K) throws(CreateKeyError) -> Data

    /// Encrypts `data` using the public key of a ``BiometryCurrentSetProtectedKey``,
    /// auto-creating the key if it does not yet exist. No authentication required.
    /// - Throws: ``EncryptError``
    func encrypt<K: BiometryCurrentSetProtectedKey>(data: Data, with key: K) throws(EncryptError) -> Data

    /// Signs `payload` using a ``BiometryCurrentSetProtectedKey`` after biometric
    /// authentication. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// Checks ``hasBiometricEnrollmentChanged(for:)`` before signing and throws
    /// ``SignBiometryCurrentSetError/enrollmentChanged(name:)`` if the enrolled
    /// biometrics have changed.
    ///
    /// - Throws: ``SignBiometryCurrentSetError``
    @BiometryActor func sign<K: BiometryCurrentSetProtectedKey>(payload: Data, with key: K, laContext: LAContext?)
        throws(SignBiometryCurrentSetError) -> Data

    /// Performs ECDH key agreement using a ``BiometryCurrentSetProtectedKey``
    /// after biometric authentication. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// `publicKey` must be an x963-encoded (uncompressed, 65-byte) P-256 key.
    /// - Throws: ``DeriveBiometryCurrentSetError``
    @BiometryActor func deriveSharedSecret<K: BiometryCurrentSetProtectedKey>(
        with key: K,
        publicKey: Data,
        laContext: LAContext?
    ) throws(DeriveBiometryCurrentSetError) -> Data

    /// Decrypts ECIES data using a ``BiometryCurrentSetProtectedKey`` after
    /// biometric authentication. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// - Throws: ``DecryptBiometryCurrentSetError``
    @BiometryActor func decrypt<K: BiometryCurrentSetProtectedKey>(
        encodedData: Data,
        with key: K,
        laContext: LAContext?
    ) throws(DecryptBiometryCurrentSetError) -> Data

    // MARK: - UserPresenceProtectedKey

    /// Explicitly creates the key pair for a ``UserPresenceProtectedKey`` and
    /// returns the DER-encoded public key. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// - Parameter key: A descriptor identifying the key to create.
    /// - Returns: DER-encoded P-256 public key data (91 bytes).
    /// - Throws: ``CreateKeyError``
    @BiometryActor func create<K: UserPresenceProtectedKey>(key: K) throws(CreateKeyError) -> Data

    /// Encrypts `data` using the public key of a ``UserPresenceProtectedKey``,
    /// auto-creating the key if it does not yet exist. No authentication required.
    /// - Throws: ``EncryptError``
    func encrypt<K: UserPresenceProtectedKey>(data: Data, with key: K) throws(EncryptError) -> Data

    /// Signs `payload` using a ``UserPresenceProtectedKey`` after biometric or
    /// passcode authentication. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// - Throws: ``SignUserPresenceError``
    @BiometryActor func sign<K: UserPresenceProtectedKey>(payload: Data, with key: K, laContext: LAContext?)
        throws(SignUserPresenceError) -> Data

    /// Performs ECDH key agreement using a ``UserPresenceProtectedKey`` after
    /// biometric or passcode authentication. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// `publicKey` must be an x963-encoded (uncompressed, 65-byte) P-256 key.
    /// - Throws: ``DeriveUserPresenceError``
    @BiometryActor func deriveSharedSecret<K: UserPresenceProtectedKey>(
        with key: K,
        publicKey: Data,
        laContext: LAContext?
    ) throws(DeriveUserPresenceError) -> Data

    /// Decrypts ECIES data using a ``UserPresenceProtectedKey`` after biometric
    /// or passcode authentication. Isolated to ``BiometryActor`` — never the main actor.
    ///
    /// - Throws: ``DecryptUserPresenceError``
    @BiometryActor func decrypt<K: UserPresenceProtectedKey>(encodedData: Data, with key: K, laContext: LAContext?)
        throws(DecryptUserPresenceError) -> Data
}
