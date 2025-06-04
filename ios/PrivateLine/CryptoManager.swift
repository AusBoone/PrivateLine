import Foundation
import CryptoKit

/// Simple cryptography helper used by the SwiftUI client.
///
/// This implementation uses ``CryptoKit`` to provide symmetric AES-GCM
/// encryption. The symmetric key is persisted in the Keychain so that
/// messages can be encrypted and decrypted locally.  This does not yet
/// provide full end-to-end encryption with other users but lays the
/// groundwork for it.
enum CryptoManager {

    /// Identifier for the symmetric key stored in the keychain.
    private static let keyAccount = "PrivateLineSymmetricKey"

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
        let sealed = try AES.GCM.seal(data, using: key)
        guard let combined = sealed.combined else {
            throw CocoaError(.coderValueNotFound)
        }
        return combined
    }

    /// Decrypt ciphertext previously produced by ``encryptMessage``.
    static func decryptMessage(_ data: Data) throws -> String {
        let key = try key()
        let sealed = try AES.GCM.SealedBox(combined: data)
        let decrypted = try AES.GCM.open(sealed, using: key)
        return String(decoding: decrypted, as: UTF8.self)
    }
}
