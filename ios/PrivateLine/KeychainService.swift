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
 * Usage examples:
 * ``KeychainService.saveToken("abc")`` – Persist the short-lived access token.
 * ``KeychainService.saveRefreshToken("def")`` – Persist the long-lived refresh
 * token.
 */

/// Simple helper for storing and retrieving values from the Keychain.
struct KeychainService {
    // Values stored here are scoped to this app and device only
    /// Keychain identifier storing the JWT access token.
    private static let tokenKey = "PrivateLineToken"
    /// Keychain identifier storing the refresh token used to obtain new JWTs.
    private static let refreshTokenKey = "PrivateLineRefreshToken"

    /// Generic helper to save arbitrary data in the keychain under ``account``.
    static func save(_ account: String, data: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]
        // Remove any existing item then store the new data
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    /// Generic helper to load arbitrary data from the keychain.
    static func loadData(account: String, context: LAContext? = nil) -> Data? {
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
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return data
    }

    /// Persist the JWT access token returned by the backend in the keychain.
    static func saveToken(_ token: String) {
        if let data = token.data(using: .utf8) {
            // Store the token string as UTF-8 data
            save(tokenKey, data: data)
        }
    }

    /// Persist the refresh token which authorizes issuing new access tokens.
    static func saveRefreshToken(_ token: String) {
        if let data = token.data(using: .utf8) {
            save(refreshTokenKey, data: data)
        }
    }

    /// Load the stored JWT token, optionally requiring biometric auth.
    static func loadToken(context: LAContext? = nil) -> String? {
        guard let data = loadData(account: tokenKey, context: context) else {
            return nil
        }
        // Convert the data back to a String
        return String(data: data, encoding: .utf8)
    }

    /// Load the stored refresh token used for automatic token renewal.
    static func loadRefreshToken(context: LAContext? = nil) -> String? {
        guard let data = loadData(account: refreshTokenKey, context: context) else {
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
