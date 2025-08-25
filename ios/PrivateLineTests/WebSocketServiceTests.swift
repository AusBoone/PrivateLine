// Tests for ``WebSocketService`` covering connection management, message
// decoding safety and reconnection logic. These tests rely on mock objects to
// avoid network calls and deterministically simulate failures or inbound
// payloads.
import XCTest
import Security
@testable import PrivateLine

/// Fake ``URLSessionWebSocketTask`` that allows tests to observe lifecycle
/// events and manually trigger receive callbacks.
final class MockWebSocketTask: URLSessionWebSocketTask {
    /// Whether ``resume`` was invoked.
    var resumed = false
    /// Whether ``cancel`` was invoked.
    var cancelled = false
    /// Stored receive handler so tests can simulate inbound messages or errors.
    var receiveHandler: ((Result<URLSessionWebSocketTask.Message, Error>) -> Void)?

    override func resume() { resumed = true }

    override func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        cancelled = true
    }

    override func receive(completionHandler: @escaping (Result<URLSessionWebSocketTask.Message, Error>) -> Void) {
        receiveHandler = completionHandler
    }

    /// Convenience helper to trigger a failure on the receive handler.
    func failOnce() {
        let err = URLError(.timedOut)
        receiveHandler?(.failure(err))
    }
}

/// ``URLSession`` subclass that hands out a sequence of ``MockWebSocketTask``
/// instances instead of making real network connections.
final class MockURLSession: URLSession {
    private var tasks: [MockWebSocketTask]
    /// Tracks how many tasks have been created so reconnection attempts can be measured.
    private(set) var createdTasks = 0

    init(tasks: [MockWebSocketTask]) {
        self.tasks = tasks
    }

    override func webSocketTask(with request: URLRequest) -> URLSessionWebSocketTask {
        createdTasks += 1
        return tasks.removeFirst()
    }
}

/// APIService stub that always returns a predefined public key.
///
/// ``WebSocketService`` queries ``publicKey(for:)`` to verify message
/// signatures.  Tests supply a deterministic key so signatures can be checked
/// without network access.
final class StubAPIService: APIService {
    private let key: String

    init(publicKey: String) {
        self.key = publicKey
        try! super.init(session: URLSession.shared,
                         baseURL: URL(string: "https://example.com/api")!)
    }

    override func publicKey(for username: String) async throws -> String {
        key
    }
}

/// Tests basic lifecycle behaviour of ``WebSocketService`` using the mocks
/// above to avoid network traffic.
final class WebSocketServiceTests: XCTestCase {
    func testDefaultInitializerCreatesPinnedSession() {
        // When no session is injected, the service should configure its own
        // ``URLSession`` with a delegate that handles certificate pinning.
        let api = try! APIService(session: URLSession.shared,
                                  baseURL: URL(string: "https://example.com/api")!)
        let service = try! WebSocketService(api: api,
                                            url: URL(string: "wss://example.com")!)

        // Use reflection to access the otherwise private session for testing.
        let mirror = Mirror(reflecting: service)
        guard let session = mirror.children.first(where: { $0.label == "session" })?.value as? URLSession else {
            return XCTFail("Unable to retrieve session via reflection")
        }

        XCTAssertNotNil(session.delegate, "Custom session should provide a delegate for pinning")
        XCTAssertFalse(session === URLSession.shared, "Service must not use URLSession.shared")
    }

    /// The initializer should refuse ``ws`` URLs and accept ``wss`` URLs to
    /// guarantee encrypted socket communication.
    func testInitializerValidatesURLScheme() {
        let api = try! APIService(session: URLSession.shared,
                                  baseURL: URL(string: "https://example.com/api")!)
        XCTAssertThrowsError(try WebSocketService(api: api,
                                                 url: URL(string: "ws://insecure")!))
        XCTAssertNoThrow(try WebSocketService(api: api,
                                              url: URL(string: "wss://secure")!))
    }

    func testConnectStartsTask() {
        // Calling connect should resume the underlying WebSocket task
        let task = MockWebSocketTask()
        let session = MockURLSession(tasks: [task])
        let api = try! APIService(session: URLSession.shared,
                                  baseURL: URL(string: "https://example.com/api")!)
        let service = try! WebSocketService(api: api,
                                            url: URL(string: "wss://example.com")!,
                                            session: session)
        service.connect(token: "abc")
        XCTAssertEqual(session.createdTasks, 1)
        XCTAssertTrue(task.resumed)
    }

    func testDisconnectCancelsTask() {
        // Disconnect should cancel the active task and prevent reconnects
        let mockTask = MockWebSocketTask()
        let session = MockURLSession(tasks: [mockTask])
        let api = try! APIService(session: URLSession.shared,
                                  baseURL: URL(string: "https://example.com/api")!)
        let service = try! WebSocketService(api: api,
                                            url: URL(string: "wss://example.com")!,
                                            session: session)
        service.connect(token: "abc")
        service.disconnect()
        XCTAssertTrue(mockTask.cancelled)
        XCTAssertEqual(session.createdTasks, 1)
    }

    func testReconnectionHappensAfterFailure() {
        // Simulate a failure and verify a second task is created after backoff
        let first = MockWebSocketTask()
        let second = MockWebSocketTask()
        let session = MockURLSession(tasks: [first, second])
        let api = try! APIService(session: URLSession.shared,
                                  baseURL: URL(string: "https://example.com/api")!)
        let service = try! WebSocketService(api: api,
                                            url: URL(string: "wss://example.com")!,
                                            session: session,
                                            baseDelay: 0.1,
                                            maxDelay: 0.2,
                                            reconnectionQueue: DispatchQueue.main)

        service.connect(token: "abc")
        // Trigger failure on the first task
        first.failOnce()

        let expectation = XCTestExpectation(description: "Reconnected")
        // Wait a little longer than the 0.1 base delay for reconnect attempt
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            if second.resumed { expectation.fulfill() }
        }

        wait(for: [expectation], timeout: 1)
        XCTAssertEqual(session.createdTasks, 2)
    }

    func testDisconnectPreventsReconnection() {
        // After a failure, calling disconnect should stop future attempts
        let first = MockWebSocketTask()
        let session = MockURLSession(tasks: [first])
        let api = try! APIService(session: URLSession.shared,
                                  baseURL: URL(string: "https://example.com/api")!)
        let service = try! WebSocketService(api: api,
                                            url: URL(string: "wss://example.com")!,
                                            session: session,
                                            baseDelay: 0.1,
                                            maxDelay: 0.2,
                                            reconnectionQueue: DispatchQueue.main)

        service.connect(token: "abc")
        first.failOnce()
        service.disconnect()

        let expectation = XCTestExpectation(description: "No reconnect")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            XCTAssertEqual(session.createdTasks, 1)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1)
    }

    /// Valid JSON payload should be decoded, verified and appended to messages.
    func testValidPayloadAppended() async throws {
        // Generate an ephemeral RSA key pair for signing.
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 4096
        ]
        var error: Unmanaged<CFError>?
        let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error)!
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        let publicData = SecKeyCopyExternalRepresentation(publicKey, &error)! as Data
        let publicB64 = publicData.base64EncodedString(options: [.lineLength64Characters])
        let publicPem = "-----BEGIN PUBLIC KEY-----\n\(publicB64)\n-----END PUBLIC KEY-----"
        let fingerprint = CryptoManager.fingerprint(of: publicPem)

        // Prepare group encryption key and ciphertext.
        let groupKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        CryptoManager.storeGroupKey(groupKey.base64EncodedString(), groupId: 1)
        let plaintext = "hello"
        let cipherData = try CryptoManager.encryptGroupMessage(plaintext, groupId: 1)
        let b64 = cipherData.base64EncodedString()

        // Sign the base64 ciphertext using RSA-PSS.
        let sigData = SecKeyCreateSignature(privateKey, .rsaSignatureMessagePSSSHA256, b64.data(using: .utf8)! as CFData, &error)! as Data
        let sigB64 = sigData.base64EncodedString()

        // Configure service with stubs and inject the crafted payload.
        let task = MockWebSocketTask()
        let session = MockURLSession(tasks: [task])
        let api = StubAPIService(publicKey: publicPem)
        let service = try WebSocketService(api: api,
                                           url: URL(string: "wss://example.com")!,
                                           session: session)
        service.connect(token: "abc")

        let socket = SocketMessage(content: b64,
                                   sender: "alice",
                                   signature: sigB64,
                                   fingerprint: fingerprint,
                                   group_id: 1,
                                   id: 42,
                                   file_id: nil)
        let json = try JSONEncoder().encode(socket)
        task.receiveHandler?(.success(.string(String(data: json, encoding: .utf8)!)))

        // Wait for async processing in ``listen`` to complete.
        let exp = expectation(description: "message processed")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { exp.fulfill() }
        await fulfillment(of: [exp], timeout: 1)

        XCTAssertEqual(service.messages.count, 1)
        XCTAssertEqual(service.messages.first?.content, plaintext)
    }

    /// Malformed JSON should be ignored and not append any message.
    func testMalformedPayloadIgnored() {
        let task = MockWebSocketTask()
        let session = MockURLSession(tasks: [task])
        let api = StubAPIService(publicKey: "dummy")
        let service = try! WebSocketService(api: api,
                                            url: URL(string: "wss://example.com")!,
                                            session: session)
        service.connect(token: "abc")

        task.receiveHandler?(.success(.string("{\"sender\":\"bob\"}")))

        // Allow async code to run.
        let exp = expectation(description: "processed")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { exp.fulfill() }
        wait(for: [exp], timeout: 1)

        XCTAssertTrue(service.messages.isEmpty)
    }

    /// Payloads exceeding ``maxPayloadBytes`` are dropped before decoding.
    func testOversizedPayloadDropped() {
        let task = MockWebSocketTask()
        let session = MockURLSession(tasks: [task])
        let api = StubAPIService(publicKey: "dummy")
        let service = try! WebSocketService(api: api,
                                            url: URL(string: "wss://example.com")!,
                                            session: session)
        service.connect(token: "abc")

        // Create a string larger than ``maxPayloadBytes``.
        let huge = String(repeating: "a", count: WebSocketService.maxPayloadBytes + 1)
        task.receiveHandler?(.success(.string(huge)))

        let exp = expectation(description: "processed")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { exp.fulfill() }
        wait(for: [exp], timeout: 1)

        XCTAssertTrue(service.messages.isEmpty)
    }
}
