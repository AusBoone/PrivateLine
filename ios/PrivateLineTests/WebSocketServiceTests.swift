import XCTest
@testable import PrivateLine

final class MockWebSocketTask: URLSessionWebSocketTask {
    var resumed = false
    var cancelled = false
    override func resume() { resumed = true }
    override func cancel(with closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        cancelled = true
    }
}

final class MockURLSession: URLSession {
    let task = MockWebSocketTask()
    private(set) var lastRequest: URLRequest?
    override func webSocketTask(with request: URLRequest) -> URLSessionWebSocketTask {
        lastRequest = request
        return task
    }
}

final class WebSocketServiceTests: XCTestCase {
    func testConnectStartsTask() {
        let session = MockURLSession()
        let service = WebSocketService(session: session)
        service.connect(token: "abc")
        XCTAssertTrue(session.task.resumed)
    }

    func testDisconnectCancelsTask() {
        let session = MockURLSession()
        let service = WebSocketService(session: session)
        service.connect(token: "abc")
        service.disconnect()
        XCTAssertTrue(session.task.cancelled)
    }
}
