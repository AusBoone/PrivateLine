// Tests for ``WebSocketService`` covering connection, reconnection, default
// session configuration and disconnection logic. These tests use mock objects
// to avoid real network calls and to deterministically simulate failures.
import XCTest
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

/// Tests basic lifecycle behaviour of ``WebSocketService`` using the mocks
/// above to avoid network traffic.
final class WebSocketServiceTests: XCTestCase {
    func testDefaultInitializerCreatesPinnedSession() {
        // When no session is injected, the service should configure its own
        // ``URLSession`` with a delegate that handles certificate pinning.
        let api = APIService(session: URLSession.shared)
        let service = WebSocketService(api: api)

        // Use reflection to access the otherwise private session for testing.
        let mirror = Mirror(reflecting: service)
        guard let session = mirror.children.first(where: { $0.label == "session" })?.value as? URLSession else {
            return XCTFail("Unable to retrieve session via reflection")
        }

        XCTAssertNotNil(session.delegate, "Custom session should provide a delegate for pinning")
        XCTAssertFalse(session === URLSession.shared, "Service must not use URLSession.shared")
    }

    func testConnectStartsTask() {
        // Calling connect should resume the underlying WebSocket task
        let task = MockWebSocketTask()
        let session = MockURLSession(tasks: [task])
        let api = APIService(session: URLSession.shared)
        let service = WebSocketService(api: api, session: session)
        service.connect(token: "abc")
        XCTAssertEqual(session.createdTasks, 1)
        XCTAssertTrue(task.resumed)
    }

    func testDisconnectCancelsTask() {
        // Disconnect should cancel the active task and prevent reconnects
        let mockTask = MockWebSocketTask()
        let session = MockURLSession(tasks: [mockTask])
        let api = APIService(session: URLSession.shared)
        let service = WebSocketService(api: api, session: session)
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
        let api = APIService(session: URLSession.shared)
        let service = WebSocketService(api: api,
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
        let api = APIService(session: URLSession.shared)
        let service = WebSocketService(api: api,
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
}
