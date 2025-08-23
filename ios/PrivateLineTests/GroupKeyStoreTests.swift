import XCTest
import Crypto
@testable import PrivateLine

/// Tests for ``GroupKeyStore`` verifying key persistence and enumeration.
final class GroupKeyStoreTests: XCTestCase {
    override func setUpWithError() throws {
        GroupKeyStore.clearAll()
    }

    override func tearDownWithError() throws {
        GroupKeyStore.clearAll()
    }

    func testSaveLoadRoundTrip() throws {
        // Store a key then load it again to ensure persistence
        let raw = Data(repeating: 0x11, count: 32)
        GroupKeyStore.store(raw.base64EncodedString(), groupId: 1)
        let loaded = GroupKeyStore.load(1)
        XCTAssertEqual(raw, loaded)
    }

    func testListAndDelete() throws {
        // Multiple keys should be tracked and deletable
        let k1 = Data(repeating: 0x22, count: 32)
        let k2 = Data(repeating: 0x33, count: 32)
        GroupKeyStore.store(k1.base64EncodedString(), groupId: 10)
        GroupKeyStore.store(k2.base64EncodedString(), groupId: 20)
        XCTAssertEqual(Set(GroupKeyStore.listGroupIds()), Set([10, 20]))
        GroupKeyStore.delete(10)
        XCTAssertFalse(GroupKeyStore.contains(10))
        XCTAssertTrue(GroupKeyStore.contains(20))
    }

    func testClearAllRemovesEverything() throws {
        GroupKeyStore.store(Data(repeating: 0x44, count: 32).base64EncodedString(), groupId: 99)
        GroupKeyStore.clearAll()
        XCTAssertTrue(GroupKeyStore.listGroupIds().isEmpty)
    }
}
