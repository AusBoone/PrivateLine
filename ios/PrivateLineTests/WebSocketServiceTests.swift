// Tests for ``WebSocketService`` covering connection and disconnection logic.
import XCTest
@testable import PrivateLine

/// Fake ``URLSessionWebSocketTask`` that records whether it was resumed or
/// cancelled so tests can assert on lifecycle behaviour.
final class MockWebSocketTask: URLSessionWebSocketTask {
    var resumed = false
    var cancelled = false
    override func resume() { resumed = true }
    override func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        cancelled = true
    }
}

/// ``URLSession`` subclass that provides a pre-created ``MockWebSocketTask``
/// instead of making real network connections.
final class MockURLSession: URLSession {
    let task = MockWebSocketTask()
    private(set) var lastRequest: URLRequest?
    override func webSocketTask(with request: URLRequest) -> URLSessionWebSocketTask {
        lastRequest = request
        return task
    }
}

/// Tests basic lifecycle behaviour of ``WebSocketService`` using the mocks
/// above to avoid network traffic.
final class WebSocketServiceTests: XCTestCase {
    func testConnectStartsTask() {
        // Calling connect should resume the underlying WebSocket task
        let session = MockURLSession()
        let service = WebSocketService(session: session)
        service.connect(token: "abc")
        XCTAssertTrue(session.task.resumed)
    }

    func testDisconnectCancelsTask() {
        // Disconnect should cancel the active task
        let session = MockURLSession()
        let service = WebSocketService(session: session)
        service.connect(token: "abc")
        service.disconnect()
        XCTAssertTrue(session.task.cancelled)
    }
}
