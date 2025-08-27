// MessageRowTests.swift
// Unit tests verifying ``MessageRow`` renders metadata for expiring and
// permanent messages. The tests inspect the view's textual description to
// confirm presence or absence of the "Expires" badge without relying on
// platform-specific rendering.
//
// Rationale:
// - Messages with ``expires_at`` should visually display an "Expires" badge.
// - Messages without an expiration timestamp must omit the badge.
//
// These tests run only when SwiftUI is available. On platforms lacking the
// framework (e.g. Linux CI builders) the ``canImport`` check skips compilation
// while still exercising the rest of the package.
#if canImport(SwiftUI)
import XCTest
import SwiftUI
@testable import PrivateLine

/// Test suite ensuring ``MessageRow`` correctly reflects expiry metadata.
final class MessageRowTests: XCTestCase {
    /// Rows for expiring messages should include the "Expires" badge text.
    func testRowWithExpiryShowsBadge() {
        let msg = Message(id: 1,
                          content: "hi",
                          file_id: nil,
                          read: nil,
                          expires_at: Date(),
                          sender: "alice",
                          signature: nil)
        let row = MessageRow(message: msg, baseURL: "https://example.com")
        let description = String(describing: row.body)
        XCTAssertTrue(description.contains("Expires"),
                      "Expiring message should display an Expires badge")
    }

    /// Rows for permanent messages should not contain the "Expires" badge.
    func testRowWithoutExpiryOmitsBadge() {
        let msg = Message(id: 2,
                          content: "hello",
                          file_id: nil,
                          read: nil,
                          expires_at: nil,
                          sender: "alice",
                          signature: nil)
        let row = MessageRow(message: msg, baseURL: "https://example.com")
        let description = String(describing: row.body)
        XCTAssertFalse(description.contains("Expires"),
                       "Non-expiring message should not display an Expires badge")
    }
}
#endif

