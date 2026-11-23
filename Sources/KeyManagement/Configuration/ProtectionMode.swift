// copyright-header:allow-exception
//
//  KeyManagement
//
//  Created by kishikawa katsumi on 2014/12/24.
//  Copyright (c) 2014 kishikawa katsumi. All rights reserved.
//  Modified by Holloh, Niklas on 06.07.26.
//

import Security

/// The device-level accessibility class for a keychain item (`kSecAttrAccessible*`).
///
/// `ProtectionMode` controls *when* the operating system permits access to the
/// keychain item that stores a key's metadata. Choosing the right value is a
/// trade-off between security and usability:
///
/// - "This device only" variants prevent the key from migrating to a new device
///   via iCloud Keychain or encrypted backup. Use them for keys that must remain
///   permanently bound to a single device.
/// - Non-"this device only" variants allow the key to migrate, which can be
///   useful for backup and restore scenarios but weakens device-binding guarantees.
///
/// The default value used by all key-trait protocols is
/// ``whenUnlockedThisDeviceOnly``. Override ``KeyDescriptor/protectionMode``
/// in your key descriptor struct only if you have a specific reason to deviate.
///
/// ```swift
/// struct BackgroundKey: UnprotectedKey {
///     let name = "com.example.background"
///     let protectionMode: ProtectionMode = .afterFirstUnlockThisDeviceOnly
/// }
/// ```
public enum ProtectionMode: String, Codable, Sendable {
    /// The item is accessible while the device is unlocked.
    ///
    /// The item migrates to a new device via encrypted backup or iCloud Keychain.
    /// Use this value when you need cross-device portability and the device is
    /// expected to be unlocked when your code runs.
    case whenUnlocked

    /// The item is accessible after the first unlock since boot, even when the
    /// device is subsequently locked.
    ///
    /// Suitable for items that background tasks or push-notification handlers must
    /// access while the device is locked. The item migrates to a new device.
    case afterFirstUnlock

    /// The item is accessible only while the device is unlocked **and** a
    /// passcode is set.
    ///
    /// If the user removes their passcode, the item is permanently deleted.
    /// The item never migrates to a new device. Use this for the highest-security
    /// scenario where you also need to guarantee the passcode requirement.
    case whenPasscodeSetThisDeviceOnly

    /// The item is accessible while the device is unlocked. The item never
    /// migrates to a new device via backup or iCloud Keychain.
    ///
    /// This is the **default** protection mode for all key-trait protocols in
    /// this library. It provides a good balance between security (device-bound)
    /// and usability (accessible whenever the screen is on).
    case whenUnlockedThisDeviceOnly

    /// The item is accessible after the first unlock since boot. The item never
    /// migrates to a new device.
    ///
    /// Suitable for background-accessible items that must remain device-bound.
    case afterFirstUnlockThisDeviceOnly

    /// The corresponding `kSecAttrAccessible` constant used when creating or
    /// querying a keychain item.
    var protectionFlag: CFString {
        switch self {
        case .whenUnlocked: kSecAttrAccessibleWhenUnlocked
        case .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock
        case .whenPasscodeSetThisDeviceOnly: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
    }
}
