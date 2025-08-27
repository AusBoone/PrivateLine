// ConversationSelectionTests.swift
// Verifies that choosing a conversation updates ChatViewModel state and
// retrieves the expected message history.
//
// These tests use a mock ``APIService`` to deterministically return predefined
// messages and groups so that selection logic can be exercised without network
// dependencies.

import XCTest
@testable import PrivateLine

/// Mock API service supplying canned responses for messages and groups.
/// Each method returns data configured by the test to simulate server output
/// for the selected conversation.
final class SelectionMockAPI: APIService {
    var directMessages: [Message] = []
    var groupMessages: [Message] = []
    var groupsList: [Group] = []

    override init(session: URLSession? = nil) {
        try! super.init(session: session, baseURL: URL(string: "https://example.com/api")!)
    }

    override func fetchMessages() async throws -> [Message] { directMessages }
    override func fetchGroupMessages(_ groupId: Int) async throws -> [Message] { groupMessages }
    override func fetchGroups() async throws -> [Group] { groupsList }
}

/// Test suite confirming that selecting a conversation refreshes ``ChatViewModel``
/// and loads the appropriate message history.
final class ConversationSelectionTests: XCTestCase {

    /// Choosing a direct contact should update ``recipient`` and fetch direct
    /// messages while clearing any group selection.
    func testSelectingDirectConversationLoadsMessages() async {
        let api = SelectionMockAPI()
        api.directMessages = [Message(id: 1, content: "hi", file_id: nil, read: true, expires_at: nil, sender: nil, signature: nil)]
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)

        await vm.selectConversation(recipient: "alice")

        XCTAssertEqual(vm.recipient, "alice")
        XCTAssertNil(vm.selectedGroup)
        XCTAssertEqual(vm.messages.map { $0.content }, ["hi"])
    }

    /// Picking a group should set ``selectedGroup`` and load that group's
    /// message history along with current group metadata.
    func testSelectingGroupConversationLoadsMessages() async {
        let api = SelectionMockAPI()
        api.groupMessages = [Message(id: 2, content: "group", file_id: nil, read: true, expires_at: nil, sender: nil, signature: nil)]
        api.groupsList = [Group(id: 2, name: "Study")]
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)

        await vm.selectConversation(groupID: 2)

        XCTAssertEqual(vm.selectedGroup, 2)
        XCTAssertEqual(vm.messages.map { $0.content }, ["group"])
        XCTAssertEqual(vm.groups.first?.id, 2)
    }
}
