import Foundation
import Security
import LocalAuthentication

/// Simple helper for storing and retrieving values from the Keychain.
struct KeychainService {
    /// Keychain identifier storing the JWT token.
    private static let tokenKey = "PrivateLineToken"

    /// Generic helper to save arbitrary data in the keychain under ``account``.
    static func save(_ account: String, data: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]
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
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return data
    }

    /// Persist the JWT token returned by the backend in the keychain.
    static func saveToken(_ token: String) {
        if let data = token.data(using: .utf8) {
            save(tokenKey, data: data)
        }
    }

    /// Load the stored JWT token, optionally requiring biometric auth.
    static func loadToken(context: LAContext? = nil) -> String? {
        guard let data = loadData(account: tokenKey, context: context) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Remove the stored token from the keychain.
    static func removeToken() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tokenKey
        ]
        SecItemDelete(query as CFDictionary)
    }
}
