import Foundation
import Security
import Crypto

/// Lightweight persistence layer for group chat AES keys.
///
/// Each key is stored in the Keychain under a unique account name so it
/// survives app restarts while remaining protected by iOS security. A list of
/// stored group identifiers is mirrored in ``UserDefaults`` to allow
/// enumeration and bulk operations.
enum GroupKeyStore {
    /// Prefix for Keychain accounts. Keys are stored as raw AES bytes.
    private static let prefix = "PrivateLineGroupKey_"
    /// UserDefaults entry containing all persisted group IDs.
    private static let listKey = "PrivateLineGroupKeyIds"

    /// Retrieve the array of stored group IDs.
    private static var ids: [Int] {
        get { UserDefaults.standard.array(forKey: listKey) as? [Int] ?? [] }
        set { UserDefaults.standard.set(newValue, forKey: listKey) }
    }

    /// Persist ``b64`` as the AES key for ``groupId``.
    static func store(_ b64: String, groupId: Int) {
        guard let data = Data(base64Encoded: b64) else { return }
        // Keys are persisted with standard device-only protection. They are not
        // bound to biometrics because group messages are not as sensitive as the
        // login token and need to be accessible for background refreshes.
        KeychainService.save(prefix + String(groupId), data: data)
        if !ids.contains(groupId) { ids.append(groupId) }
    }

    /// Load the raw AES key for ``groupId`` if it exists.
    static func load(_ groupId: Int) -> Data? {
        try? KeychainService.loadData(account: prefix + String(groupId))
    }

    /// Load all persisted keys as ``SymmetricKey`` instances.
    static func loadAll() -> [Int: SymmetricKey] {
        var map: [Int: SymmetricKey] = [:]
        for id in ids {
            if let data = load(id) {
                map[id] = SymmetricKey(data: data)
            }
        }
        return map
    }

    /// Return ``true`` if a key is saved for ``groupId``.
    static func contains(_ groupId: Int) -> Bool {
        load(groupId) != nil
    }

    /// Delete the persisted key for ``groupId``.
    static func delete(_ groupId: Int) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: prefix + String(groupId)
        ]
        SecItemDelete(query as CFDictionary)
        ids.removeAll { $0 == groupId }
    }

    /// List all group IDs with persisted keys.
    static func listGroupIds() -> [Int] { ids }

    /// Remove all stored keys from the Keychain and memory list.
    static func clearAll() {
        for id in ids { delete(id) }
    }

    /// Export all keys as base64 strings for migration or debugging.
    static func exportAll() -> [Int: String] {
        var out: [Int: String] = [:]
        for id in ids {
            if let data = load(id) {
                out[id] = data.base64EncodedString()
            }
        }
        return out
    }
}
