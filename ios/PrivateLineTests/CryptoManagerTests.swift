import XCTest
@testable import PrivateLine

final class CryptoManagerTests: XCTestCase {
    func testEncryptDecryptMessage() throws {
        let message = "Hello, world!"
        let encrypted = try CryptoManager.encryptMessage(message)
        let decrypted = try CryptoManager.decryptMessage(encrypted)
        XCTAssertEqual(decrypted, message)
    }
}
