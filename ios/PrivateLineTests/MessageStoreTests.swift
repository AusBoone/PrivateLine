import XCTest
@testable import PrivateLine

/// Verifies the lightweight disk cache used by the iOS client.

extension Message: Equatable {}

/// Ensures messages persist to disk and can be reloaded accurately.
final class MessageStoreTests: XCTestCase {
    let fileURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("messages.json")

    override func setUpWithError() throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? FileManager.default.removeItem(at: fileURL)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: fileURL)
    }

    func testSaveLoadRoundTrip() throws {
        // Persist messages then verify they round-trip correctly
        let messages = [
            Message(id: 1, content: "Hi", file_id: nil, read: true),
            Message(id: 2, content: "Bye", file_id: nil, read: false)
        ]
        MessageStore.save(messages)
        sleep(1)
        let loaded = MessageStore.load()
        XCTAssertEqual(loaded, messages)
    }
}
