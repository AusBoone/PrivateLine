import XCTest
@testable import PrivateLine

/*
 * MessageStoreTests.swift
 * ----------------------
 * Unit tests validating the message caching layer. The tests focus on
 * verifying that messages are encrypted on disk and that the persistence API
 * performs a lossless round-trip when the correct key is available.
 */

// Extend ``Message`` with ``Equatable`` so arrays can be compared in tests.
extension Message: Equatable {}

/// Test suite exercising the ``MessageStore`` persistence logic.
final class MessageStoreTests: XCTestCase {
    /// Location of the encrypted cache file used for test fixtures.
    let fileURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("messages.json")

    override func setUpWithError() throws {
        // Ensure a clean directory exists for each test run.
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try? FileManager.default.removeItem(at: fileURL)
    }

    override func tearDownWithError() throws {
        // Clean up the cache file after each test so cases remain isolated.
        try? FileManager.default.removeItem(at: fileURL)
    }

    /// Persist messages then verify they round-trip correctly through the
    /// encryption and decoding pipeline.
    func testSaveLoadRoundTrip() throws {
        let messages = [
            Message(id: 1, content: "Hi", file_id: nil, read: true, expires_at: nil, sender: nil, signature: nil),
            Message(id: 2, content: "Bye", file_id: nil, read: false, expires_at: nil, sender: nil, signature: nil)
        ]

        MessageStore.save(messages)
        sleep(1) // Allow background save to complete before reading.
        let loaded = MessageStore.load()
        XCTAssertEqual(loaded, messages)
    }

    /// Ensure that the encrypted file cannot be decoded without first
    /// decrypting using ``CryptoManager``.
    func testDataUnreadableWithoutDecryption() throws {
        let messages = [
            Message(id: 1, content: "Secret", file_id: nil, read: true, expires_at: nil, sender: nil, signature: nil)
        ]

        // Save the message and wait for the asynchronous write to finish.
        MessageStore.save(messages)
        sleep(1)

        let raw = try Data(contentsOf: fileURL)

        // Attempting to decode the encrypted blob directly should fail because
        // the bytes are not valid JSON without decryption.
        XCTAssertThrowsError(try JSONDecoder().decode([Message].self, from: raw))

        // Additionally ensure that obvious plaintext is absent to highlight
        // that the data is indeed encrypted.
        let rawString = String(data: raw, encoding: .utf8)
        XCTAssertFalse(rawString?.contains("Secret") ?? false)
    }
}
