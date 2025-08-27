/*
 * MessageRow.swift - Reusable SwiftUI view for rendering a single chat message.
 *
 * This component encapsulates the visual representation of a message including
 * bubble styling, timestamp and expiry indicator. It is used by ``ChatView`` to
 * display conversation history.
 *
 * Usage example:
 * ```swift
 * List(messages) { msg in
 *     MessageRow(message: msg, baseURL: api.baseURLString)
 * }
 * ```
 *
 * Design decisions:
 * - The message bubble aligns to the leading edge for incoming messages and to
 *   the trailing edge for messages authored by the local user (identified by a
 *   ``nil`` sender field).
 * - ``expires_at`` triggers a small "Expires" badge to communicate ephemerality
 *   to the user.
 * - A formatted timestamp is derived from ``id`` which represents the message's
 *   creation time in seconds since the epoch when generated locally. Server
 *   provided identifiers may not encode time but are still rendered for
 *   consistency.
 */
import SwiftUI

/// Visual representation of a single chat message including metadata.
struct MessageRow: View {
    /// Message being presented within the row.
    let message: Message
    /// Base URL string used to build download links for attachments.
    let baseURL: String

    /// Convenience flag identifying whether the message was authored by the
    /// current user. Messages sent from this device are stored with a ``nil``
    /// sender which we interpret as local.
    private var isCurrentUser: Bool { message.sender == nil }

    /// Time the message was created, formatted for display. Because the backend
    /// does not expose an explicit timestamp, we interpret ``id`` as a Unix
    /// epoch when locally generated. If ``id`` does not represent a valid time
    /// the date formatter gracefully falls back to the Unix epoch.
    private var formattedTimestamp: String {
        let date = Date(timeIntervalSince1970: TimeInterval(message.id))
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    var body: some View {
        HStack {
            if isCurrentUser { Spacer() }
            VStack(alignment: isCurrentUser ? .trailing : .leading, spacing: 4) {
                // Message bubble with text and optional attachment link.
                VStack(alignment: isCurrentUser ? .trailing : .leading, spacing: 2) {
                    Text(message.content)
                    if let fid = message.file_id {
                        Link("attachment", destination: URL(string: "\(baseURL)/files/\(fid)")!)
                    }
                }
                .padding(8)
                .background(isCurrentUser ? Color.blue : Color.gray.opacity(0.2))
                .foregroundColor(isCurrentUser ? .white : .black)
                .cornerRadius(12)

                // Timestamp, read receipt and optional expiry badge.
                HStack(spacing: 4) {
                    Text(formattedTimestamp)
                        .font(.caption2)
                        .foregroundColor(.gray)
                    if let read = message.read, isCurrentUser, message.id != 0 {
                        Image(systemName: read ? "checkmark.circle.fill" : "checkmark.circle")
                            .foregroundColor(.gray)
                    }
                    if message.expires_at != nil {
                        Text("Expires")
                            .font(.caption2)
                            .padding(2)
                            .background(Color.red.opacity(0.8))
                            .foregroundColor(.white)
                            .cornerRadius(4)
                            .accessibilityLabel("Expires")
                    }
                }
            }
            if !isCurrentUser { Spacer() }
        }
        .padding(.vertical, 2)
        .accessibilityLabel("Message: \(message.content)")
    }
}

