// ChatViewAlertTests.swift
// Ensures ``ChatView`` surfaces ``lastError`` via an alert and resets the
// error when the user dismisses the alert.
//
// Test rationale:
// - ``lastError`` should cause the alert binding to report "presented".
// - Dismissing the alert via the binding should clear ``lastError`` so future
//   failures trigger new alerts.

import XCTest
import SwiftUI
@testable import PrivateLine

/// Test suite verifying that the alert bound to ``ChatView``
/// reacts to ``lastError`` changes as expected.
final class ChatViewAlertTests: XCTestCase {
    /// ``lastError`` should drive alert presentation.
    /// Setting it non-nil must cause the binding to indicate the alert is shown.
    func testAlertAppearsWhenLastErrorSet() throws {
        // Provide stub services so the view model operates without network I/O.
        let api = MockAPIService()
        let socket = try! WebSocketService(
            api: api,
            url: URL(string: "wss://example.com")!,
            session: URLSession(configuration: .ephemeral)
        )
        let vm = ChatViewModel(api: api, socket: socket)
        var view = ChatView(viewModel: vm)

        // Simulate a failure surfaced by the view model.
        vm.lastError = "Network down"

        // Binding should evaluate to true indicating the alert is showing.
        XCTAssertTrue(view.errorAlertBinding.wrappedValue)
    }

    /// Dismissing the alert should clear ``lastError`` so additional failures
    /// surface new alerts.
    func testDismissingAlertClearsLastError() throws {
        let api = MockAPIService()
        let socket = try! WebSocketService(
            api: api,
            url: URL(string: "wss://example.com")!,
            session: URLSession(configuration: .ephemeral)
        )
        let vm = ChatViewModel(api: api, socket: socket)
        var view = ChatView(viewModel: vm)

        // Start with a presentable error.
        vm.lastError = "Send failed"
        XCTAssertTrue(view.errorAlertBinding.wrappedValue)

        // Simulate the user dismissing the alert by toggling the binding off.
        view.errorAlertBinding.wrappedValue = false

        // ``lastError`` should now be cleared allowing future errors to display.
        XCTAssertNil(vm.lastError)
    }
}
