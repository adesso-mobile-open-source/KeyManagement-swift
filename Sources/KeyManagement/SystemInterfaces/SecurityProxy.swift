//
//  SecurityProxy.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 21.08.25 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import Security
import Spyable

/// A thin protocol seam over the Security framework functions used by
/// `SecureEnclaveKeyStore`.
///
/// Every Security framework function called by `SecureEnclaveKeyStore` is
/// exposed through this protocol, making the production implementation
/// (`SecurityProxyImpl`) swappable with a test spy (`SecurityProxySpy`,
/// generated in DEBUG builds by the `@Spyable` macro). This follows the
/// hexagonal-architecture / ports-and-adapters pattern: the protocol is the
/// port and `SecurityProxyImpl` is the adapter.
///
/// Protocol methods mirror the signatures of the corresponding Security
/// framework functions exactly. Refer to the individual method documentation
/// or to `<Security/Security.h>` for full API contracts.
///
/// > Note: A `SecurityProxySpy` is automatically generated in DEBUG builds
/// > by the `swift-spyable` macro. Use it in unit tests to inspect call
/// > arguments and return stubbed values without requiring the Secure Enclave.
///
/// > Note: The Apple documentation copied below explicitly warns that
/// > operations on access-control-protected keys can block the calling
/// > thread. This library honours that warning by isolating every
/// > biometry-gated `KeyManager` operation to ``KeyManagementActor`` — a
/// > dedicated background actor — instead of `MainActor`. See
/// > ``KeyManagementActor`` for details.
@Spyable(behindPreprocessorFlag: "DEBUG") public protocol SecurityProxy: Sendable {
    /// @function secAccessControlCreateWithFlags
    /// @abstract Creates new access control object based on protection type and additional flags.
    /// @discussion Created access control object should be used as a value for kSecAttrAccessControl attribute in
    /// SecItemAdd, SecItemUpdate or SecKeyGeneratePair functions. Accessing keychain items or performing operations
    /// on keys which are protected by access control objects can block the execution because of UI which can appear
    /// to satisfy the access control conditions, therefore it is recommended to either move those potentially
    /// blocking operations out of the main application thread or use combination of kSecUseAuthenticationContext and
    /// kSecUseAuthenticationUI attributes to control where the UI interaction can appear.
    /// @param allocator Allocator to be used by this instance.
    /// @param protection Protection class to be used for the item. One of kSecAttrAccessible constants.
    /// @param flags If no flags are set then all operations are allowed.
    /// @param error Additional error information filled in case of failure.
    /// @result Newly created access control object.
    func secAccessControlCreateWithFlags(
        _ allocator: CFAllocator?,
        _ protection: CFTypeRef,
        _ flags: SecAccessControlCreateFlags,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecAccessControl?

    /// @function secKeyCreateRandomKey
    /// @abstract Generates a new public/private key pair.
    /// @param parameters A dictionary containing one or more key-value pairs.
    ///   See the discussion sections below for a complete overview of options.
    /// @param error On error, will be populated with an error object describing the failure.
    /// See "Security Error Codes" (SecBase.h).
    /// @return Newly generated private key. To get associated public key, use SecKeyCopyPublicKey().
    /// @discussion In order to generate a keypair the parameters dictionary must
    ///   at least contain the following keys:
    ///
    /// * kSecAttrKeyType with a value being kSecAttrKeyTypeRSA or any other
    /// kSecAttrKeyType defined in SecItem.h
    /// * kSecAttrKeySizeInBits with a value being a CFNumberRef or CFStringRef
    /// containing the requested key size in bits. Example sizes for RSA
    /// keys are: 512, 768, 1024, 2048.
    ///
    /// The values below may be set either in the top-level dictionary or in a
    /// dictionary that is the value of the kSecPrivateKeyAttrs or
    /// kSecPublicKeyAttrs key in the top-level dictionary. Setting these
    /// attributes explicitly will override the defaults below. See SecItem.h
    /// for detailed information on these attributes including the types of
    /// the values.
    ///
    /// * kSecAttrLabel default NULL
    /// * kSecAttrIsPermanent if this key is present and has a Boolean value of true,
    ///  the key or key pair will be added to the default keychain.
    /// * kSecAttrTokenID if this key should be generated on specified token. This
    ///  attribute can contain CFStringRef and can be present only in the top-level
    ///  parameters dictionary.
    /// * kSecAttrApplicationTag default NULL
    /// * kSecAttrEffectiveKeySize default NULL same as kSecAttrKeySizeInBits
    /// * kSecAttrCanEncrypt default false for private keys, true for public keys
    /// * kSecAttrCanDecrypt default true for private keys, false for public keys
    /// * kSecAttrCanDerive default true
    /// * kSecAttrCanSign default true for private keys, false for public keys
    /// * kSecAttrCanVerify default false for private keys, true for public keys
    /// * kSecAttrCanWrap default false for private keys, true for public keys
    /// * kSecAttrCanUnwrap default true for private keys, false for public keys
    func secKeyCreateRandomKey(_ parameters: CFDictionary, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?)
        -> SecKey?

    ///    @function secItemDelete
    ///    @abstract Delete zero or more items which match a search query.
    ///    @param query A dictionary containing an item class specification and
    ///        optional attributes for controlling the search. See the "Attribute
    ///        Constants" and "Search Constants" sections for a description of
    ///        currently defined search attributes.
    ///    @result A result code. See "Security Error Codes" (SecBase.h).
    ///    @discussion Attributes defining a search are specified by adding key/value
    ///        pairs to the query dictionary.
    ///
    ///    By default, this function deletes all items matching the specified query.
    ///    You can change this behavior by specifying one of the follow keys:
    ///
    ///      * To delete an item identified by a transient reference, on iOS, specify
    ///        kSecValueRef with a item reference. On macOS, give a kSecMatchItemList
    ///        containing an item reference.
    ///      * To delete an item identified by a persistent reference, on iOS, specify
    ///        kSecValuePersistentRef with a persistent reference returned by
    ///        using the kSecReturnPersistentRef key to SecItemCopyMatching or
    ///        SecItemAdd. On macOS, use kSecMatchItemList with a persistent reference
    ///        returned by using the kSecReturnPersistentRef key with
    ///        SecItemCopyMatching or SecItemAdd.
    ///      * To delete multiple items specify kSecMatchItemList with an array
    ///        of references.
    ///      * If more than one of these result keys is specified, the behavior is
    ///        undefined.
    func secItemDelete(_ query: CFDictionary) -> OSStatus

    ///    @function secItemCopyMatching
    ///    @abstract Returns one or more items which match a search query.
    ///    @param query A dictionary containing an item class specification and
    ///        optional attributes for controlling the search. See the "Keychain
    ///        Search Attributes" section for a description of currently defined
    ///        search attributes.
    ///    @param result On return, a CFTypeRef reference to the found item(s). The
    ///        exact type of the result is based on the search attributes supplied
    ///        in the query, as discussed below.
    ///    @result A result code. See "Security Error Codes" (SecBase.h).
    ///    @discussion Attributes defining a search are specified by adding key/value
    ///        pairs to the query dictionary.
    ///
    ///    A typical query consists of:
    ///
    ///      * a kSecClass key, whose value is a constant from the Class
    ///        Constants section that specifies the class of item(s) to be searched
    ///      * one or more keys from the "Attribute Key Constants" section, whose value
    ///        is the attribute data to be matched
    ///      * one or more keys from the "Search Constants" section, whose value is
    ///        used to further refine the search
    ///      * a key from the "Return Type Key Constants" section, specifying the type of
    ///        results desired
    ///
    ///   Result types are specified as follows:
    ///
    ///      * To obtain the data of a matching item (CFDataRef), specify
    ///        kSecReturnData with a value of kCFBooleanTrue.
    ///      * To obtain the attributes of a matching item (CFDictionaryRef), specify
    ///        kSecReturnAttributes with a value of kCFBooleanTrue.
    ///      * To obtain a reference to a matching item (SecKeychainItemRef,
    ///        SecKeyRef, SecCertificateRef, or SecIdentityRef), specify kSecReturnRef
    ///        with a value of kCFBooleanTrue. Note that returning references is
    ///        supported only for Certificate, Key or Identity items on iOS, watchOS and
    ///        tvOS. Similarly, returning references is supported only for Certificate, Key
    ///        or Identity items on macOS when either kSecUseDataProtectionKeychain
    ///        is set to true or kSecAttrSynchronizable is set to true.
    ///      * To obtain a persistent reference to a matching item (CFDataRef),
    ///        specify kSecReturnPersistentRef with a value of kCFBooleanTrue. Note
    ///        that unlike normal references, a persistent reference may be stored
    ///        on disk or passed between processes.
    ///      * If more than one of these result types is specified, the result is
    ///        returned as a CFDictionaryRef containing all the requested data.
    ///      * If a result type is not specified, no results are returned.
    ///
    ///    By default, this function returns only the first match found. To obtain
    ///    more than one matching item at a time, specify kSecMatchLimit with a value
    ///    greater than 1. The result will be a CFArrayRef containing up to that
    ///    number of matching items; the items' types are described above.
    ///
    ///    To filter a provided list of items down to those matching the query,
    ///    specify a kSecMatchItemList whose value is a CFArray of SecKeychainItemRef,
    ///    SecKeyRef, SecCertificateRef, or SecIdentityRef items. The objects in the
    ///    provided array must be of the same type.
    ///
    ///    On iOS, to convert from a persistent item reference to a normal item reference,
    ///    specify a kSecValuePersistentRef whose value a CFDataRef (the persistent
    ///    reference), and a kSecReturnRef whose value is kCFBooleanTrue.
    ///
    ///    On macOS, to convert from persistent item references to normal item references,
    ///    specify a kSecMatchItemList whose value is a CFArray containing one or
    ///    more CFDataRef elements (the persistent reference), and a kSecReturnRef
    ///    whose value is kCFBooleanTrue. The objects in the provided array must be
    ///    of the same type.
    func secItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus

    /// @function secKeyCopyExternalRepresentation
    /// @abstract Get external representation of the given key suitable for the key's type.
    /// @param key Key for which external representation is to be obtained.
    /// @param error Error which is filled in if the operation fails. Pass NULL if not interested.
    /// @return External representation of the key, or NULL if operation fails.
    /// @discussion Returned data can be passed to SecKeyCreateWithData() to recreate the key.
    /// For public keys, external representation is the same as the key data returned by SecKeyCopyAttributes().
    /// For private keys, external representation varies by key type and may not be available for all key types.
    func secKeyCopyExternalRepresentation(_ key: SecKey, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData?

    /// @function secKeyCreateSignature
    /// @abstract Given a private key and data to sign, generate a digital signature.
    /// @param key Private key with which to sign.
    /// @param algorithm One of SecKeyAlgorithm constants suitable to the private key.
    /// @param dataToSign The data to be signed, typically the digest of the actual data.
    /// @param error Error which is filled in if the operation fails. Pass NULL if not interested.
    /// @return Signature, or NULL on failure.
    func secKeyCreateSignature(
        _ key: SecKey,
        _ algorithm: SecKeyAlgorithm,
        _ dataToSign: CFData,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> CFData?

    ///   @function SecKeyCreateWithData
    ///   @abstract Create a SecKey from a well-defined external representation.
    ///   @param keyData CFData representing the key. The format of the data depends on the type of key being created.
    ///   @param attributes Dictionary containing attributes describing the key to be imported. The keys in this
    ///   dictionary are kSecAttr* constants from SecItem.h. Mandatory attributes are:
    ///    * kSecAttrKeyType
    ///    * kSecAttrKeyClass
    ///   @param error On error, will be populated with an error object describing the failure.
    ///   See "Security Error Codes" (SecBase.h).
    ///   @result A SecKey object representing the key, or NULL on failure.
    ///   @discussion This function does not add keys to any keychain, but the SecKey object it returns can be added
    ///   to keychain using the SecItemAdd function.
    ///   The requested data format depend on the type of key (kSecAttrKeyType) being created:
    ///    * kSecAttrKeyTypeRSA               PKCS#1 format, public key can be also in x509 public key format
    ///    * kSecAttrKeyTypeECSECPrimeRandom  ANSI X9.63 format (04 || X || Y [ || K])
    func secKeyCreateWithData(
        _ keyData: CFData,
        _ attributes: CFDictionary,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecKey?

    /// @function SecKeyCopyKeyExchangeResult
    /// @abstract Perform Diffie-Hellman style of key exchange operation, optionally with additional key-derivation
    /// steps.
    /// @param algorithm One of SecKeyAlgorithm constants suitable to perform this operation.
    /// @param publicKey Remote party's public key.
    /// @param parameters Dictionary with parameters, see SecKeyKeyExchangeParameter constants. Used algorithm
    /// determines the set of required and optional parameters to be used.
    /// @param error Pointer to an error object on failure.
    /// See "Security Error Codes" (SecBase.h).
    /// @result Result of key exchange operation as a CFDataRef, or NULL on failure.
    func secKeyCopyKeyExchangeResult(
        _ privateKey: SecKey,
        _ algorithm: SecKeyAlgorithm,
        _ publicKey: SecKey,
        _ parameters: CFDictionary,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> CFData?
}

/// The production `SecurityProxy` implementation that forwards every call
/// directly to the corresponding `Security.framework` function.
///
/// Instantiate and inject this type into `SecureEnclaveKeyStore` when running
/// on a real device with a Secure Enclave. In unit tests, use the
/// auto-generated `SecurityProxySpy` (available in DEBUG builds) instead.
public struct SecurityProxyImpl: SecurityProxy {
    /// Creates a new `SecurityProxyImpl` instance.
    public init() {}

    public func secAccessControlCreateWithFlags(
        _ allocator: CFAllocator?,
        _ protection: CFTypeRef,
        _ flags: SecAccessControlCreateFlags,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecAccessControl? { Security.SecAccessControlCreateWithFlags(allocator, protection, flags, error) }

    public func secKeyCreateRandomKey(_ parameters: CFDictionary, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?)
        -> SecKey? { Security.SecKeyCreateRandomKey(parameters, error) }

    public func secItemDelete(_ query: CFDictionary) -> OSStatus { Security.SecItemDelete(query) }

    public func secItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
        Security.SecItemCopyMatching(query, result)
    }

    public func secKeyCopyExternalRepresentation(_ key: SecKey, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?)
        -> CFData? { Security.SecKeyCopyExternalRepresentation(key, error) }

    public func secKeyCreateSignature(
        _ key: SecKey,
        _ algorithm: SecKeyAlgorithm,
        _ dataToSign: CFData,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> CFData? { Security.SecKeyCreateSignature(key, algorithm, dataToSign, error) }

    public func secKeyCreateWithData(
        _ keyData: CFData,
        _ attributes: CFDictionary,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> SecKey? { Security.SecKeyCreateWithData(keyData, attributes, error) }

    public func secKeyCopyKeyExchangeResult(
        _ privateKey: SecKey,
        _ algorithm: SecKeyAlgorithm,
        _ publicKey: SecKey,
        _ parameters: CFDictionary,
        _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
    ) -> CFData? { Security.SecKeyCopyKeyExchangeResult(privateKey, algorithm, publicKey, parameters, error) }
}
