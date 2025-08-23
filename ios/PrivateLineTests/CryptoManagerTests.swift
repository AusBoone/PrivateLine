// Unit tests for ``CryptoManager`` verifying symmetric and group encryption
// helpers along with Secure Enclave backed RSA signing and decryption. The
// tests exercise both successful hardware-backed flows and graceful failure
// when Secure Enclave support is missing.
import XCTest
import CryptoKit
import Security
@testable import PrivateLine

/// Exercises the symmetric, group and Secure Enclave backed RSA helper
/// functions provided by ``CryptoManager``.
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

    /// Verify that supplying mismatched AAD during decryption triggers an error.
    /// This guards against tampering with associated metadata such as message
    /// identifiers or recipients.
    func testDecryptDataFailsWithWrongAAD() throws {
        let payload = "secret".data(using: .utf8)!
        let goodAAD = "1:bob".data(using: .utf8)!
        // Encrypt the payload with contextual AAD.
        let encrypted = try CryptoManager.encryptData(payload, aad: goodAAD)
        // Decryption with the correct AAD should restore the plaintext.
        let roundTrip = try CryptoManager.decryptData(encrypted, aad: goodAAD)
        XCTAssertEqual(roundTrip, payload)
        // Using a different AAD simulates tampering and must throw.
        let badAAD = "2:bob".data(using: .utf8)!
        XCTAssertThrowsError(try CryptoManager.decryptData(encrypted, aad: badAAD))
    }

    /// Verify Secure Enclave key generation, signing and decryption.
    /// If the Secure Enclave is unavailable the test is skipped.
    func testSecureEnclaveRoundTrip() throws {
        do {
            try CryptoManager.loadPrivateKey(password: "")
        } catch {
            throw XCTSkip("Secure Enclave unavailable: \(error)")
        }

        // Fetch the generated key so we can access its public component for
        // encrypting a test message. The tag mirrors CryptoManager.secureKeyTag.
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.privateline.securekey".data(using: .utf8)!,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        SecItemCopyMatching(query as CFDictionary, &item)
        guard let privateKey = item as? SecKey,
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            XCTFail("Secure Enclave key not found")
            return
        }

        let message = "hello"

        // Signing should succeed with the hardware-backed key.
        let signature = try CryptoManager.signMessage(message)
        var error: Unmanaged<CFError>?
        XCTAssertTrue(
            SecKeyVerifySignature(
                publicKey,
                .rsaSignatureMessagePSSSHA256,
                message.data(using: .utf8)! as CFData,
                signature as CFData,
                &error
            )
        )

        // Encrypt using the public key and ensure decryption with CryptoManager.
        let cipher = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionOAEPSHA256,
            message.data(using: .utf8)! as CFData,
            &error
        )! as Data
        let decrypted = try CryptoManager.decryptRSA(cipher.base64EncodedString())
        XCTAssertEqual(decrypted, message)
    }

    /// Ensure operations fail cleanly when Secure Enclave support is absent.
    func testSecureEnclaveUnavailable() throws {
        do {
            try CryptoManager.loadPrivateKey(password: "")
            throw XCTSkip("Secure Enclave present; skipping negative test")
        } catch {
            XCTAssertThrowsError(try CryptoManager.signMessage("hi"))
            XCTAssertThrowsError(
                try CryptoManager.decryptRSA(Data([1]).base64EncodedString())
            )
        }
    }

    /// Verify double ratchet roundtrip and forward secrecy.
    func testRatchetRoundTripAndAdvance() throws {
        let root = Data(repeating: 9, count: 32).base64EncodedString()
        CryptoManager.storeRatchetRoot(root, conversationId: "test1")
        defer { CryptoManager.removeRatchetState("test1") }
        let payload = "secret".data(using: .utf8)!
        let (cipher, nonce) = try CryptoManager.ratchetEncrypt(payload, conversationId: "test1")
        let plain = try CryptoManager.ratchetDecrypt(cipher, nonce: nonce, conversationId: "test1")
        XCTAssertEqual(plain, payload)
        // Decrypting again with the rotated key should fail.
        XCTAssertThrowsError(
            try CryptoManager.ratchetDecrypt(cipher, nonce: nonce, conversationId: "test1")
        )
    }

    /// Ensure ratchet state persists in the keychain and survives cache clears.
    func testRatchetPersistence() throws {
        let root = Data(repeating: 10, count: 32).base64EncodedString()
        CryptoManager.storeRatchetRoot(root, conversationId: "persist")
        defer { CryptoManager.removeRatchetState("persist") }
        // Encrypt once to populate cache then drop it.
        _ = try CryptoManager.ratchetEncrypt(Data([1, 2, 3]), conversationId: "persist")
        CryptoManager.clearRatchetCache()
        let (cipher, nonce) = try CryptoManager.ratchetEncrypt(Data([4, 5]), conversationId: "persist")
        _ = try CryptoManager.ratchetDecrypt(cipher, nonce: nonce, conversationId: "persist")
    }
}
