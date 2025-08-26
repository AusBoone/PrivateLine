// ChatViewErrorHandlingTests.swift
// Validates that ``ChatViewModel`` can surface consecutive errors by resetting
// ``lastError`` after an alert dismissal. This mirrors ``ChatView``'s runtime
// behaviour of clearing the error when the user taps the alert's confirmation
// button. Ensures UI alerts appear for repeated failures.
//
// Test rationale:
// - After clearing ``lastError`` a subsequent assignment should succeed.
// - Helps guard against regressions where stale errors suppress new ones.

import XCTest
@testable import PrivateLine

/// Test suite verifying ``lastError`` can be reset to allow future alerts.
final class ChatViewErrorHandlingTests: XCTestCase {
    /// Setting, clearing and reassigning ``lastError`` should always reflect the
    /// most recent value. The view relies on this to present multiple sequential
    /// alerts when consecutive operations fail.
    func testLastErrorCanBeClearedForSubsequentAlerts() throws {
        // Provide stubbed dependencies so the view model operates without
        // external network interactions.
        let api = MockAPIService()
        let socket = try! WebSocketService(
            api: api,
            url: URL(string: "wss://example.com")!,
            session: URLSession(configuration: .ephemeral)
        )
        let vm = ChatViewModel(api: api, socket: socket)

        // First error surfaces as expected
        vm.lastError = "First"
        XCTAssertEqual(vm.lastError, "First")

        // Simulate alert dismissal by clearing the error
        vm.lastError = nil
        XCTAssertNil(vm.lastError)

        // Second error should be accepted and visible to observers
        vm.lastError = "Second"
        XCTAssertEqual(vm.lastError, "Second")
    }
}
