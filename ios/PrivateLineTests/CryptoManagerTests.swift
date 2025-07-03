// Unit tests for ``CryptoManager`` verifying symmetric and group encryption
// helpers including RSA round trips and signing.
import XCTest
import CryptoKit
import Security
import CommonCrypto
@testable import PrivateLine

/// Exercises the symmetric, group and RSA helper functions provided by
/// ``CryptoManager``.
final class CryptoManagerTests: XCTestCase {
    func testEncryptDecryptMessage() throws {
        // Symmetric encryption roundtrip should restore the original string
        let message = "Hello, world!"
        let encrypted = try CryptoManager.encryptMessage(message)
        let decrypted = try CryptoManager.decryptMessage(encrypted)
        XCTAssertEqual(decrypted, message)
    }

    func testGroupEncryptionRoundtrip() throws {
        // Messages encrypted with a group key should decrypt with the same key
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        CryptoManager.storeGroupKey(key, groupId: 1)
        let encrypted = try CryptoManager.encryptGroupMessage("hi", groupId: 1)
        let decrypted = try CryptoManager.decryptGroupMessage(encrypted, groupId: 1)
        XCTAssertEqual(decrypted, "hi")
    }

    func testGroupKeyPersistsAcrossLoads() throws {
        // Persist a group key then drop the cache and reload from disk
        let b64 = Data(repeating: 2, count: 32).base64EncodedString()
        CryptoManager.storeGroupKey(b64, groupId: 5)
        CryptoManager.clearKeyCache()
        CryptoManager.preloadPersistedGroupKeys()
        let enc = try CryptoManager.encryptGroupMessage("test", groupId: 5)
        let dec = try CryptoManager.decryptGroupMessage(enc, groupId: 5)
        XCTAssertEqual(dec, "test")
    }

    func testRemoveGroupKeyPreventsUse() throws {
        let b64 = Data(repeating: 3, count: 32).base64EncodedString()
        CryptoManager.storeGroupKey(b64, groupId: 6)
        CryptoManager.removeGroupKey(6)
        XCTAssertThrowsError(try CryptoManager.encryptGroupMessage("hi", groupId: 6))
    }

    func testListingAndClearingKeys() throws {
        CryptoManager.storeGroupKey(Data(repeating: 4, count: 32).base64EncodedString(), groupId: 7)
        CryptoManager.storeGroupKey(Data(repeating: 5, count: 32).base64EncodedString(), groupId: 8)
        XCTAssertEqual(Set(CryptoManager.listGroupIds()), Set([7, 8]))
        CryptoManager.clearAllGroupKeys()
        XCTAssertTrue(CryptoManager.listGroupIds().isEmpty)
    }

    /// Generate a temporary RSA key pair and verify CryptoManager helpers
    func testRSAEncryptDecryptAndSign() throws {
        // Generate ephemeral RSA key pair
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        let publicKey = SecKeyCopyPublicKey(privateKey)!

        // Convert keys to PEM strings
        let pubData = SecKeyCopyExternalRepresentation(publicKey, &error)! as Data
        let publicPem = pemString(for: pubData, header: "-----BEGIN PUBLIC KEY-----", footer: "-----END PUBLIC KEY-----")
        let privData = SecKeyCopyExternalRepresentation(privateKey, &error)! as Data
        let privatePem = pemString(for: privData, header: "-----BEGIN PRIVATE KEY-----", footer: "-----END PRIVATE KEY-----")

        // Encrypt and store key material, then load the private key
        let password = "testing"
        let salt = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let derived = try deriveKey(password: password, salt: salt)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(Data(privatePem.utf8), using: derived, nonce: nonce)
        let ciphertext = sealed.ciphertext + sealed.tag
        let material = CryptoManager.KeyMaterial(
            encrypted_private_key: ciphertext.base64EncodedString(),
            salt: salt.base64EncodedString(),
            nonce: Data(sealed.nonce).base64EncodedString(),
            fingerprint: nil)
        CryptoManager.storeKeyMaterial(material)
        try CryptoManager.loadPrivateKey(password: password)

        // Test RSA encryption/decryption helpers
        let message = "hello"
        let encrypted = try CryptoManager.encryptRSA(message, publicKeyPem: publicPem)
        let decrypted = try CryptoManager.decryptRSA(encrypted.base64EncodedString())
        XCTAssertEqual(decrypted, message)

        // Test signing and verification helpers
        let sig = try CryptoManager.signMessage(message)
        let verified = SecKeyVerifySignature(
            publicKey,
            .rsaSignatureMessagePSSSHA256,
            message.data(using: .utf8)! as CFData,
            sig as CFData,
            &error
        )
        XCTAssertTrue(verified)
    }

    private func pemString(for data: Data, header: String, footer: String) -> String {
        let b64 = data.base64EncodedString(options: [.lineLength64Characters])
        return header + "\n" + b64 + "\n" + footer
    }

    private func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        var derived = Data(count: 32)
        let status = derived.withUnsafeMutableBytes { derivedBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password,
                    password.utf8.count,
                    saltBytes.bindMemory(to: UInt8.self).baseAddress!,
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    200000,
                    derivedBytes.bindMemory(to: UInt8.self).baseAddress!,
                    32
                )
            }
        }
        guard status == kCCSuccess else { throw NSError(domain: "PBKDF2", code: Int(status)) }
        return SymmetricKey(data: derived)
    }
}
