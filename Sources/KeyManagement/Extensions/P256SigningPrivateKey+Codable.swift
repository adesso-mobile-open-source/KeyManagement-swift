//
//  P256SigningPrivateKey+Codable.swift
//  KeyManagement
//
//  Created by Holloh, Niklas on 22.08.25 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

import CryptoKit
import Foundation

// Retroactive `Codable` conformance for `P256.Signing.PrivateKey`.
//
// This conformance is required so that `SoftwareKeyStore.KeyWrapper` (which
// bundles a private key with its associated password) can be serialised by
// `PersistentKeyValueStore` and persisted between app launches. The `@retroactive`
// attribute suppresses the Swift compiler warning about conformances for types
// defined in another module.
//
// The conformance encodes the key using its DER representation (PKCS #8 /
// SEC 1), which is a stable, interoperable format. On decode the DER bytes are
// passed directly to `P256.Signing.PrivateKey.init(derRepresentation:)`.
//
// Note: Ideally this conformance would be `internal`, but the Swift compiler
// requires it to be `public` because `P256.Signing.PrivateKey` is a public
// type from an external module (`CryptoKit`). Do not rely on this conformance
// from outside the `KeyManagement` module.

/// Retroactive `Decodable` conformance for `P256.Signing.PrivateKey`.
///
/// Decodes from a single `Data` value containing the DER representation of
/// the private key (as produced by `P256.Signing.PrivateKey.derRepresentation`).
/// This conformance is an internal implementation detail of `SoftwareKeyStore`
/// and should not be used directly from outside the `KeyManagement` module.
extension P256.Signing.PrivateKey: @retroactive Decodable {
    /// Creates a `P256.Signing.PrivateKey` by decoding a DER-encoded key
    /// from the given decoder.
    ///
    /// - Parameter decoder: The decoder to read key data from.
    /// - Throws: `DecodingError` if the container cannot be read, or
    ///   `CryptoKitError` if the decoded bytes are not a valid P-256 private
    ///   key in DER format.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let data = try container.decode(Data.self)
        try self.init(derRepresentation: data)
    }
}

/// Retroactive `Encodable` conformance for `P256.Signing.PrivateKey`.
///
/// Encodes the key as a single `Data` value containing its DER representation
/// (`P256.Signing.PrivateKey.derRepresentation`). This conformance is an
/// internal implementation detail of `SoftwareKeyStore` and should not be
/// used directly from outside the `KeyManagement` module.
extension P256.Signing.PrivateKey: @retroactive Encodable {
    /// Encodes this `P256.Signing.PrivateKey` into the given encoder using
    /// its DER representation.
    ///
    /// - Parameter encoder: The encoder to write key data to.
    /// - Throws: `EncodingError` if the container cannot be written to.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(derRepresentation)
    }
}
