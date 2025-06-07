// Unit tests for CryptoManager verifying symmetric and group encryption helpers.
import XCTest
@testable import PrivateLine

final class CryptoManagerTests: XCTestCase {
    func testEncryptDecryptMessage() throws {
        let message = "Hello, world!"
        let encrypted = try CryptoManager.encryptMessage(message)
        let decrypted = try CryptoManager.decryptMessage(encrypted)
        XCTAssertEqual(decrypted, message)
    }

    func testGroupEncryptionRoundtrip() throws {
        let key = Data(repeating: 1, count: 32).base64EncodedString()
        CryptoManager.storeGroupKey(key, groupId: 1)
        let encrypted = try CryptoManager.encryptGroupMessage("hi", groupId: 1)
        let decrypted = try CryptoManager.decryptGroupMessage(encrypted, groupId: 1)
        XCTAssertEqual(decrypted, "hi")
    }
}
