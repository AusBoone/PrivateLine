import Foundation
import Security
import LocalAuthentication

/*
 * KeychainService.swift
 * ---------------------
 * Utilities for persisting sensitive authentication material in the iOS
 * keychain. Both access and refresh tokens are stored using distinct keys so
 * that they remain isolated from other app data and protected by the system.
 *
 * 2025 security hardening:
 * - All items now specify ``kSecAttrAccessibleWhenUnlockedThisDeviceOnly`` to
 *   ensure values never sync via iCloud and are available only after the device
 *   has been unlocked.
 * - Access tokens are additionally bound to ``.biometryCurrentSet`` meaning a
 *   successful Face ID/Touch ID scan is required before retrieval and the token
 *   becomes invalid if biometrics are re-enrolled.
 * - ``loadData`` surfaces ``LAError`` values so callers can react to biometric
 *   failures instead of receiving silent ``nil`` values.
 *
 * Usage examples:
 * ``KeychainService.saveToken("abc")`` – Persist the short-lived access token.
 * ``KeychainService.saveRefreshToken("def")`` – Persist the long-lived refresh
 * token.
 */

/// Simple helper for storing and retrieving values from the Keychain.
///
/// The helper intentionally scopes all entries to this device only and, when
/// requested, binds values to the current biometric set.  This prevents tokens
/// from syncing via iCloud and ensures Face ID/Touch ID is required before the
/// sensitive data is returned.
struct KeychainService {
    // Values stored here are scoped to this app and device only
    /// Keychain identifier storing the JWT access token.
    private static let tokenKey = "PrivateLineToken"
    /// Keychain identifier storing the refresh token used to obtain new JWTs.
    private static let refreshTokenKey = "PrivateLineRefreshToken"

    /// Generic helper to save arbitrary data in the keychain under ``account``.
    /// - Parameters:
    ///   - account: Logical key used as ``kSecAttrAccount``.
    ///   - data: Raw bytes to persist.
    ///   - requiresBiometry: When ``true`` the item is protected by the current
    ///     biometric set so retrieval requires Face ID/Touch ID.
    static func save(_ account: String, data: Data, requiresBiometry: Bool = false) {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]

        // All items are limited to this device and only available when the user
        // has unlocked it at least once since reboot.
        let accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        if requiresBiometry {
            // Bind the entry to the current biometric set. If the user
            // re-enrolls Face ID/Touch ID the item becomes inaccessible.
            var error: Unmanaged<CFError>?
            if let ac = SecAccessControlCreateWithFlags(nil, accessibility, .biometryCurrentSet, &error) {
                query[kSecAttrAccessControl as String] = ac
            }
        } else {
            // For non-biometric items just set the accessibility attribute.
            query[kSecAttrAccessible as String] = accessibility
        }

        // Remove any existing item then store the new data
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    /// Generic helper to load arbitrary data from the keychain.
    /// - Parameters:
    ///   - account: Logical key used as ``kSecAttrAccount``.
    ///   - context: Optional ``LAContext`` used for biometric evaluation. When
    ///     provided, failures are surfaced as ``LAError`` values so callers can
    ///     react accordingly (e.g. showing an error message).
    /// - Returns: The stored bytes or ``nil`` when not found.
    static func loadData(account: String, context: LAContext? = nil) throws -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: kCFBooleanTrue as Any,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if let ctx = context {
            query[kSecUseAuthenticationContext as String] = ctx
        }

        var item: AnyObject?
        // Attempt to read the value from the keychain
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecUserCanceled:
            // User dismissed the biometric prompt
            throw LAError(.userCancel)
        case errSecAuthFailed:
            // Authentication failed (e.g. Face ID mismatch)
            throw LAError(.authenticationFailed)
        default:
            return nil
        }
    }

    /// Persist the JWT access token returned by the backend in the keychain.
    static func saveToken(_ token: String) {
        if let data = token.data(using: .utf8) {
            // Store the token string as UTF-8 data guarded by biometrics
            save(tokenKey, data: data, requiresBiometry: true)
        }
    }

    /// Persist the refresh token which authorizes issuing new access tokens.
    static func saveRefreshToken(_ token: String) {
        if let data = token.data(using: .utf8) {
            save(refreshTokenKey, data: data)
        }
    }

    /// Load the stored JWT token, prompting for biometrics when required.
    static func loadToken(context: LAContext = LAContext()) throws -> String? {
        guard let data = try loadData(account: tokenKey, context: context) else {
            return nil
        }
        // Convert the data back to a String
        return String(data: data, encoding: .utf8)
    }

    /// Load the stored refresh token used for automatic token renewal.
    static func loadRefreshToken(context: LAContext = LAContext()) throws -> String? {
        guard let data = try loadData(account: refreshTokenKey, context: context) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Remove the stored access token from the keychain.
    static func removeToken() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tokenKey
        ]
        // Delete the keychain entry
        SecItemDelete(query as CFDictionary)
    }

    /// Remove the stored refresh token from the keychain.
    static func removeRefreshToken() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: refreshTokenKey
        ]
        SecItemDelete(query as CFDictionary)
    }
}
