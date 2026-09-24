// copyright-header:allow-exception
//  Created by kishikawa katsumi on 2014/12/24.
//  Copyright (c) 2014 kishikawa katsumi. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//
//  AuthenticationOptions.swift
//  AMSBiometry
//
//  Modified by Holloh, Niklas on 07.04.25.
//

import Security

struct AuthenticationOptions: OptionSet, Sendable {
    /// User presence policy using Touch ID or Passcode. Touch ID does not
    /// have to be available or enrolled. Item is still accessible by Touch ID
    /// even if fingers are added or removed.
    static let userPresence = Self(rawValue: 1 << 0)

    /// Constraint: Touch ID (any finger) or Face ID. Touch ID or Face ID must be available. With Touch ID
    /// at least one finger must be enrolled. With Face ID user has to be enrolled. Item is still accessible by
    /// Touch ID even if fingers are added or removed. Item is still accessible by Face ID if user is re-enrolled.
    static let biometryAny = Self(rawValue: 1 << 1)

    /// Constraint: Touch ID from the set of currently enrolled fingers. Touch ID must be available and at least one
    /// finger must be enrolled. When fingers are added or removed, the item is invalidated. When Face ID is
    /// re-enrolled this item is invalidated.
    static let biometryCurrentSet = Self(rawValue: 1 << 3)

    /// Constraint: Device passcode
    static let devicePasscode = Self(rawValue: 1 << 4)

    /// Constraint: Watch
    @available(iOS, unavailable) @available(macOS 10.15, *) @available(watchOS, unavailable)
    @available(tvOS, unavailable) static let watch = Self(rawValue: 1 << 5)

    /// Constraint logic operation: when using more than one constraint,
    /// at least one of them must be satisfied.
    static let or = Self(rawValue: 1 << 14)

    /// Constraint logic operation: when using more than one constraint,
    /// all must be satisfied.
    static let and = Self(rawValue: 1 << 15)

    /// Create access control for private key operations (i.e. sign operation)
    static let privateKeyUsage = Self(rawValue: 1 << 30)

    /// Security: Application provided password for data encryption key generation.
    /// This is not a constraint but additional item encryption mechanism.
    static let applicationPassword = Self(rawValue: 1 << 31)

    let rawValue: UInt

    /// Create a new AuthenticationOptions set by its raw value.
    /// - Parameter rawValue: The raw value of the AuthenticationOptions OptionSet.
    init(rawValue: UInt) { self.rawValue = rawValue }

    var flags: SecAccessControlCreateFlags { SecAccessControlCreateFlags(rawValue: rawValue) }
}
