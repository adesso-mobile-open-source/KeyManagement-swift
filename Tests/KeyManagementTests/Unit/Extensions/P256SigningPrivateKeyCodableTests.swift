//
//  P256SigningPrivateKeyCodableTests.swift
//  KeyManagement
//
//  Created by Feistel, Simon on 11.09.26 for adesso SE.
//
//  Copyright 2026 adesso SE
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0

//
//  Tests for P256.Signing.PrivateKey Codable conformance
//

import CryptoKit
@testable import KeyManagement

struct P256SigningPrivateKeyCodableTests {
    @Test("encode when given private key produces DER data that reinitializes key")
    func encode_whenGivenPrivateKey_producesDERDataThatReinitializesKey() throws {
        // Given
        let originalKey = P256.Signing.PrivateKey()

        // When
        let data = try JSONEncoder().encode(originalKey)
        let decodedKey = try JSONDecoder().decode(P256.Signing.PrivateKey.self, from: data)

        // Then
        // DER representation of the decoded key should match original
        #expect(decodedKey.derRepresentation == originalKey.derRepresentation)
    }

    @Test("decode when given invalid data throws") func decode_whenGivenInvalidData_throws() throws {
        // Given
        // Construct invalid JSON (not base64 for Data or wrong structure) -> We'll encode an int instead of Data
        // Single value container expecting Data base64 string, this will fail decoding.
        let invalidJSON = Data("123".utf8)

        // When / Then
        #expect(throws: Error.self) { _ = try JSONDecoder().decode(P256.Signing.PrivateKey.self, from: invalidJSON) }
    }

    @Test("encode when encoding multiple keys independently produces distinct data")
    func encode_whenEncodingMultipleKeysIndependently_producesDistinctData() throws {
        // Given
        let key1 = P256.Signing.PrivateKey()
        let key2 = P256.Signing.PrivateKey()

        // When
        let data1 = try JSONEncoder().encode(key1)
        let data2 = try JSONEncoder().encode(key2)

        // Then
        #expect(data1 != data2)
        // Also ensure each round-trips
        let roundTrip1 = try JSONDecoder().decode(P256.Signing.PrivateKey.self, from: data1)
        let roundTrip2 = try JSONDecoder().decode(P256.Signing.PrivateKey.self, from: data2)
        #expect(roundTrip1.derRepresentation == key1.derRepresentation)
        #expect(roundTrip2.derRepresentation == key2.derRepresentation)
    }
}
