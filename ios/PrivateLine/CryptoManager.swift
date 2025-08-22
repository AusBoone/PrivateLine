//
//  CryptoManager.swift
//  PrivateLine
//
//  Central cryptographic utilities for the iOS client.  The module exposes
//  helpers for symmetric encryption, group key persistence and RSA operations.
//  RSA private keys are generated inside the Secure Enclave and only a keychain
//  reference is kept, ensuring hardware-backed protection.  When the Secure
//  Enclave is unavailable (e.g. on the simulator) operations will throw
//  descriptive errors so the caller can gracefully degrade.
//
import Foundation
import CryptoKit
import Security

// GroupKeyStore persists AES keys in the keychain so chats remain
// decryptable after the app restarts.
// swiftlint:disable type_body_length

/// Simple cryptography helper used by the SwiftUI client.
///
/// This implementation uses ``CryptoKit`` to provide symmetric AES-GCM
/// encryption for persisted data and RSA-OAEP for message exchange.
/// The symmetric key is stored in the Keychain and messages are
/// encrypted locally before being transmitted, enabling end-to-end
/// security across clients.
enum CryptoManager {

    /// Identifier for the symmetric key stored in the keychain.
    private static let keyAccount = "PrivateLineSymmetricKey"
    /// Keychain entry containing the encrypted RSA private key material.
    private static let materialAccount = "PrivateLineKeyMaterial"

    /// Application tag used to locate the Secure Enclave key in the keychain.
    /// The tag acts as a persistent identifier so the key can be retrieved
    /// across launches without storing the key material itself.
    private static let secureKeyTag = "com.privateline.securekey"

    /// Errors surfaced when interacting with the Secure Enclave.  These errors
    /// allow calling code to distinguish between missing hardware and other
    /// operational issues.
    enum SecureEnclaveError: Error {
        /// Returned when the device lacks Secure Enclave support.
        case unavailable
        /// Returned when the private key cannot be located in the keychain.
        case keyNotFound
    }

    /// Helper struct describing the encrypted key material returned by the backend.
    struct KeyMaterial: Codable {
        let encrypted_private_key: String
        let salt: String
        let nonce: String
        let fingerprint: String?
    }

    /// Persist encrypted key material to the keychain.
    static func storeKeyMaterial(_ material: KeyMaterial) {
        if let data = try? JSONEncoder().encode(material) {
            KeychainService.save(materialAccount, data: data)
        }
    }

    /// Load previously stored key material from the keychain.
    private static func loadKeyMaterial() -> KeyMaterial? {
        guard let data = KeychainService.loadData(account: materialAccount) else {
            return nil
        }
        return try? JSONDecoder().decode(KeyMaterial.self, from: data)
    }

    /// Return the stored fingerprint if available
    static func fingerprint() -> String? {
        return loadKeyMaterial()?.fingerprint
    }

    /// Fetch the AES key from the keychain or generate one if needed.
    private static func key() throws -> SymmetricKey {
        if let data = KeychainService.loadData(account: keyAccount),
           !data.isEmpty {
            return SymmetricKey(data: data)
        }
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        KeychainService.save(keyAccount, data: keyData)
        return key
    }

    /// Encrypt ``message`` using AES-GCM with the stored key.
    static func encryptMessage(_ message: String) throws -> Data {
        let key = try key()
        let data = Data(message.utf8)
        // Encrypt and authenticate the data using AES-GCM
        let sealed = try AES.GCM.seal(data, using: key)
        guard let combined = sealed.combined else {
            throw CocoaError(.coderValueNotFound)
        }
        return combined
    }

    /// Decrypt ciphertext previously produced by ``encryptMessage``.
    static func decryptMessage(_ data: Data) throws -> String {
        let key = try key()
        // Open the sealed box and verify authenticity
        let sealed = try AES.GCM.SealedBox(combined: data)
        let decrypted = try AES.GCM.open(sealed, using: key)
        return String(decoding: decrypted, as: UTF8.self)
    }

    /// Encrypt arbitrary binary data with the stored key.
    static func encryptData(_ data: Data) throws -> Data {
        let key = try key()
        let sealed = try AES.GCM.seal(data, using: key)
        guard let combined = sealed.combined else { throw CocoaError(.coderValueNotFound) }
        return combined
    }

    /// Decrypt data previously encrypted with ``encryptData``.
    static func decryptData(_ data: Data) throws -> Data {
        let key = try key()
        let sealed = try AES.GCM.SealedBox(combined: data)
        let decrypted = try AES.GCM.open(sealed, using: key)
        return decrypted
    }

    // MARK: - Group encryption helpers

    /// Cached per-group symmetric keys held in memory.
    private static var groupKeys: [Int: SymmetricKey] = [:]

    /// Persist ``b64`` as the AES key for ``groupId`` and cache it in memory.
    static func storeGroupKey(_ b64: String, groupId: Int) {
        guard let data = Data(base64Encoded: b64), data.count == 32 else { return }
        groupKeys[groupId] = SymmetricKey(data: data)
        GroupKeyStore.store(b64, groupId: groupId)
    }

    /// Load all saved keys from the Keychain into ``groupKeys``.
    static func preloadPersistedGroupKeys() {
        groupKeys = GroupKeyStore.loadAll()
    }

    /// Remove the cached key and delete it from the Keychain.
    static func removeGroupKey(_ groupId: Int) {
        groupKeys[groupId] = nil
        GroupKeyStore.delete(groupId)
    }

    /// Clear in-memory keys without touching persisted values.
    static func clearKeyCache() {
        groupKeys.removeAll()
    }

    /// Remove all keys from memory and the Keychain.
    static func clearAllGroupKeys() {
        groupKeys.removeAll()
        GroupKeyStore.clearAll()
    }

    /// ``true`` if a key exists either in memory or in persistent storage.
    static func hasGroupKey(_ groupId: Int) -> Bool {
        groupKeys[groupId] != nil || GroupKeyStore.contains(groupId)
    }

    /// List all known group IDs from memory and disk.
    static func listGroupIds() -> [Int] {
        let mem = Set(groupKeys.keys)
        let disk = Set(GroupKeyStore.listGroupIds())
        return Array(mem.union(disk)).sorted()
    }

    /// Export all stored keys as base64 strings.
    static func exportAllGroupKeys() -> [Int: String] {
        var result: [Int: String] = [:]
        for (id, key) in groupKeys {
            let data = key.withUnsafeBytes { Data($0) }
            result[id] = data.base64EncodedString()
        }
        for (id, b64) in GroupKeyStore.exportAll() where result[id] == nil {
            result[id] = b64
        }
        return result
    }

    /// Encrypt a message with the shared group key.
    static func encryptGroupMessage(_ message: String, groupId: Int) throws -> Data {
        var key = groupKeys[groupId]
        if key == nil, let data = GroupKeyStore.load(groupId) {
            key = SymmetricKey(data: data)
            groupKeys[groupId] = key
        }
        guard let useKey = key else { throw CocoaError(.coderValueNotFound) }
        let data = Data(message.utf8)
        let sealed = try AES.GCM.seal(data, using: useKey)
        guard let combined = sealed.combined else { throw CocoaError(.coderValueNotFound) }
        return combined
    }

    /// Decrypt a group message previously encrypted with ``encryptGroupMessage``.
    static func decryptGroupMessage(_ data: Data, groupId: Int) throws -> String {
        var key = groupKeys[groupId]
        if key == nil, let data = GroupKeyStore.load(groupId) {
            key = SymmetricKey(data: data)
            groupKeys[groupId] = key
        }
        guard let useKey = key else { throw CocoaError(.coderValueNotFound) }
        let sealed = try AES.GCM.SealedBox(combined: data)
        let decrypted = try AES.GCM.open(sealed, using: useKey)
        return String(decoding: decrypted, as: UTF8.self)
    }

    // MARK: - RSA helper functions

    /// Retrieve the Secure Enclave private key from the keychain.
    /// - Returns: ``SecKey`` reference if the key exists, otherwise ``nil``.
    private static func fetchSecureEnclaveKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: secureKeyTag.data(using: .utf8)!,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    /// Ensure a Secure Enclave RSA key pair exists for the application.
    /// - Parameter password: Unused legacy parameter kept for API stability.
    /// - Throws: ``SecureEnclaveError.unavailable`` when the hardware cannot
    ///   generate the key (e.g. running on the simulator).
    static func loadPrivateKey(password _: String = "") throws {
        // If the key already exists, no further work is necessary.
        if fetchSecureEnclaveKey() != nil { return }

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            nil
        ) else {
            throw SecureEnclaveError.unavailable
        }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 4096,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: secureKeyTag.data(using: .utf8)!,
            kSecAttrAccessControl as String: access
        ]
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attrs as CFDictionary, &error) != nil else {
            throw SecureEnclaveError.unavailable
        }
    }

    /// Encrypt ``message`` with ``publicKeyPem`` using RSA-OAEP.
    static func encryptRSA(_ message: String, publicKeyPem: String) throws -> Data {
        let b64 = publicKeyPem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
        guard let data = Data(base64Encoded: b64) else { throw CocoaError(.coderInvalidValue) }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 4096
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        let plain = message.data(using: .utf8)!
        guard let cipher = SecKeyCreateEncryptedData(key, .rsaEncryptionOAEPSHA256, plain as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return cipher
    }

    /// Decrypt base64-encoded ciphertext using the Secure Enclave private key.
    /// - Parameter b64: RSA ciphertext encoded as base64.
    /// - Returns: The decrypted plaintext string.
    static func decryptRSA(_ b64: String) throws -> String {
        guard let data = Data(base64Encoded: b64) else {
            throw CocoaError(.coderInvalidValue)
        }
        guard let key = fetchSecureEnclaveKey() else {
            throw SecureEnclaveError.keyNotFound
        }
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(key, .rsaEncryptionOAEPSHA256, data as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return String(decoding: decrypted, as: UTF8.self)
    }

    /// Sign ``message`` using the Secure Enclave private key with RSA-PSS.
    /// The signature can be verified by recipients using the corresponding
    /// public key which never leaves the device unencrypted.
    /// - Parameter message: UTF-8 string to sign.
    /// - Returns: Raw signature bytes.
    static func signMessage(_ message: String) throws -> Data {
        guard let key = fetchSecureEnclaveKey() else {
            throw SecureEnclaveError.keyNotFound
        }
        let data = message.data(using: .utf8)!
        var error: Unmanaged<CFError>?
        // Produce a PSS signature over the UTF-8 bytes
        guard let sig = SecKeyCreateSignature(key, .rsaSignatureMessagePSSSHA256, data as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return sig
    }

    /// Compute SHA256 fingerprint of a PEM-encoded public key
    static func fingerprint(of pem: String) -> String {
        let b64 = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
        // Compute the SHA256 hash of the DER data
        let data = Data(base64Encoded: b64) ?? Data()
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }
}
