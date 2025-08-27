// ChatViewModelTests.swift
// Unit tests for ``ChatViewModel`` covering error propagation during message
// sending and contact retrieval. The API layer is mocked so tests run
// deterministically without network access.
//
// These tests ensure that failures during file upload, message transmission or
// contact fetching are surfaced via ``lastError`` and that no local state such
// as message lists, input text or contact arrays are mutated on failure.

import XCTest
@testable import PrivateLine

/// Mock ``APIService`` that can be toggled to throw from its network methods.
/// This lets tests simulate typical failure scenarios such as connectivity
/// issues or authentication errors.
final class MockAPIService: APIService {
    enum Failure: Error { case upload, send, contacts }

    /// Control flags injected by individual tests to trigger failures.
    var uploadShouldFail = false
    var directSendShouldFail = false
    var groupSendShouldFail = false
    var contactsShouldFail = false
    /// Artificial delay inserted before returning to simulate network latency.
    var delayNanoseconds: UInt64 = 0

    override init(session: URLSession? = nil) {
        // Provide a secure base URL so the superclass initializer succeeds
        // without relying on Info.plist values.
        try! super.init(session: session,
                        baseURL: URL(string: "https://example.com/api")!)
    }

    override func uploadFile(
        data: Data,
        filename: String,
        messageId: Int? = nil,
        recipient: String? = nil,
        groupId: Int? = nil
    ) async throws -> Int? {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        if uploadShouldFail { throw Failure.upload }
        return 1
    }

    override func sendMessage(_ content: String, to recipient: String, fileId: Int? = nil, expiresAt: Date? = nil) async throws {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        if directSendShouldFail { throw Failure.send }
    }

    override func sendGroupMessage(_ content: String, groupId: Int, fileId: Int? = nil, expiresAt: Date? = nil) async throws {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        if groupSendShouldFail { throw Failure.send }
    }

    override func fetchContacts() async throws -> [String] {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        if contactsShouldFail { throw Failure.contacts }
        return ["alice", "bob"]
    }

    override func fetchMessages() async throws -> [Message] {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        return []
    }
    override func fetchGroups() async throws -> [Group] {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        return []
    }
}

/// Test suite verifying ``ChatViewModel`` surfaces errors without mutating
/// local state on failure.
final class ChatViewModelTests: XCTestCase {

    /// Upload failures should set ``lastError`` and leave the composed message
    /// intact so the user can retry without retyping.
    func testUploadFailureSetsError() async {
        let api = MockAPIService()
        api.uploadShouldFail = true
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)
        vm.input = "hi"
        vm.attachment = Data([0x0])
        await vm.send()

        XCTAssertNotNil(vm.lastError)
        XCTAssertTrue(vm.messages.isEmpty)
        XCTAssertEqual(vm.input, "hi")
        XCTAssertFalse(vm.isLoading)
    }

    /// Sending the text message should surface an error when the API rejects
    /// the request and should not append to ``messages``.
    func testDirectSendFailureSetsError() async {
        let api = MockAPIService()
        api.directSendShouldFail = true
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)
        vm.input = "hello"
        await vm.send()

        XCTAssertNotNil(vm.lastError)
        XCTAssertTrue(vm.messages.isEmpty)
        XCTAssertFalse(vm.isLoading)
    }

    /// Group message failures should also set ``lastError`` and avoid altering
    /// local message history.
    func testGroupSendFailureSetsError() async {
        let api = MockAPIService()
        api.groupSendShouldFail = true
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)
        vm.input = "hey"
        vm.selectedGroup = 1
        await vm.send()

        XCTAssertNotNil(vm.lastError)
        XCTAssertTrue(vm.messages.isEmpty)
        XCTAssertFalse(vm.isLoading)
    }

    /// Contact retrieval failures should set ``lastError`` and result in an
    /// empty ``contacts`` array so the UI does not display stale usernames.
    func testContactFetchFailureSetsError() async {
        let api = MockAPIService()
        api.contactsShouldFail = true
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)
        await vm.fetchContacts()

        XCTAssertNotNil(vm.lastError)
        XCTAssertTrue(vm.contacts.isEmpty)
    }

    /// Successful contact retrieval populates the ``contacts`` list used by the
    /// picker in ``ChatView``.
    func testFetchContactsPopulatesList() async {
        let api = MockAPIService()
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)
        await vm.fetchContacts()

        XCTAssertEqual(vm.contacts, ["alice", "bob"])
        XCTAssertNil(vm.lastError)
    }

    /// ``send()`` should set ``isLoading`` while network calls execute and
    /// clear it once finished so the UI hides the progress indicator.
    func testSendTogglesLoadingState() async {
        let api = MockAPIService()
        api.delayNanoseconds = 50_000_000
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)
        vm.input = "loading"
        let task = Task { await vm.send() }
        await Task.yield()
        XCTAssertTrue(vm.isLoading)
        await task.value
        XCTAssertFalse(vm.isLoading)
    }

    /// ``load()`` also toggles ``isLoading`` so the chat shows an activity
    /// indicator while refreshing history.
    func testLoadTogglesLoadingState() async {
        let api = MockAPIService()
        api.delayNanoseconds = 50_000_000
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)
        let task = Task { await vm.load() }
        await Task.yield()
        XCTAssertTrue(vm.isLoading)
        await task.value
        XCTAssertFalse(vm.isLoading)
    }

    /// Selecting an attachment should store both the raw data and filename so
    /// ``ChatView`` can present a meaningful preview to the user.
    func testSelectingAttachmentStoresDataAndName() throws {
        let api = MockAPIService()
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)
        let sample = Data([0x0, 0x1])
        vm.selectAttachment(data: sample, filename: "note.txt")

        XCTAssertEqual(vm.attachment, sample)
        XCTAssertEqual(vm.attachmentFilename, "note.txt")
    }

    /// ``removeAttachment()`` should clear both the stored data and filename so
    /// subsequent selections do not display stale previews.
    func testRemoveAttachmentClearsState() throws {
        let api = MockAPIService()
        let socket = try! WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: URLSession(configuration: .ephemeral))
        let vm = ChatViewModel(api: api, socket: socket)
        vm.selectAttachment(data: Data([0x2]), filename: "temp.bin")
        vm.removeAttachment()

        XCTAssertNil(vm.attachment)
        XCTAssertNil(vm.attachmentFilename)
    }
}

