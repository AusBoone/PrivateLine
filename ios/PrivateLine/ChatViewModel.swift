/*
 * ChatViewModel.swift - Observable store backing ChatView.
 * Coordinates message loading, sending and WebSocket updates.
 *
 * Modifications:
 * - Added ``lastError`` published property surfaced when message sending or
 *   loading fails so views can present actionable alerts.
 * - Wrapped calls to ``APIService`` with explicit error capture to guide users
 *   through typical failure scenarios such as connectivity loss or expired
 *   authentication.
 */
import Foundation
import Combine

@MainActor
/// State container for ``ChatView`` handling message fetching, sending and
/// WebSocket updates.
final class ChatViewModel: ObservableObject {
    /// Decrypted messages currently displayed in the chat view.
    @Published var messages: [Message] = []
    /// Text typed by the user before sending.
    @Published var input = ""
    /// Username of the current direct message recipient.
    @Published var recipient = "bob"
    /// Available chat groups pulled from the backend.
    @Published var groups: [Group] = []
    /// Identifier of the selected group chat if the user is chatting in a group.
    /// ``nil`` indicates a direct person-to-person conversation.
    @Published var selectedGroup: Int? = nil
    /// Binary data for an optional file attachment.
    @Published var attachment: Data? = nil
    /// Minutes after which newly sent messages should expire. ``0`` means no
    /// expiration and messages persist indefinitely.
    @Published var expiresInMinutes: Double = 0
    /// Human readable description of the most recent error. ``nil`` when the
    /// last operation succeeded. Views observe this value to surface alerts and
    /// suggest retry actions.
    @Published var lastError: String? = nil

    /// Backend API wrapper used for all network operations.
    let api: APIService
    /// WebSocket service providing real-time updates.
    private let socket: WebSocketService
    /// Subscriptions to updates from ``socket``.
    private var cancellables = Set<AnyCancellable>()

    /// Create a new view model using an ``APIService`` instance.
    init(api: APIService) {
        self.api = api
        // WebSocket service depends on ``APIService`` for key fetching and
        // signature verification of inbound messages.
        self.socket = WebSocketService(api: api)
    }

    /// Fetch messages from the server and establish the WebSocket connection.
    /// Local cached messages are loaded first so the UI can display immediately
    /// while the network request is in flight.
    func load() async {
        // Load cached messages first for offline support
        // Remove locally cached messages that have already expired
        let cached = MessageStore.load().filter { msg in
            guard let exp = msg.expires_at else { return true }
            return exp > Date()
        }
        messages = cached
        do {
            // Retrieve available chat groups
            groups = try await api.fetchGroups()
            // Fetch either direct or group conversation history
            let fetched = try await (selectedGroup != nil ? api.fetchGroupMessages(selectedGroup!) : api.fetchMessages())
            let valid = fetched.filter { msg in
                guard let exp = msg.expires_at else { return true }
                return exp > Date()
            }
            messages = valid
            // Mark unread messages as read on the server
            for msg in fetched where msg.read != true && (msg.id != 0) {
                try? await api.markMessageRead(id: msg.id)
            }
            // Persist the updated history locally
            MessageStore.save(valid)
            // Establish WebSocket connection for real-time updates
            if let token = api.authToken {
                socket.connect(token: token)
            }
            // Update local messages whenever new ones arrive
            socket.$messages.sink { [weak self] msgs in
                let valid = msgs.filter { msg in
                    guard let exp = msg.expires_at else { return true }
                    return exp > Date()
                }
                self?.messages = valid
                MessageStore.save(valid)
            }.store(in: &cancellables)
        } catch {
            // Typical failures include connectivity loss, server errors or
            // expired authentication tokens. Reset state and surface the error so
            // the UI can prompt the user to retry or re-authenticate.
            messages = []
            lastError = "Load failed: \(error.localizedDescription)"
        }
    }

    /// Encrypt and send the current input to the selected recipient or group.
    /// Attachments are uploaded first and the returned file id included in the
    /// message body. On success the plaintext is appended locally so the UI
    /// feels responsive while waiting for the server.
    func send() async {
        // Clear any previous error so the view reflects only the latest attempt.
        lastError = nil

        var fileId: Int? = nil
        if let data = attachment {
            do {
                // Upload attachment first so the returned id can be included
                fileId = try await api.uploadFile(data: data, filename: "file")
                attachment = nil
            } catch {
                // Upload can fail due to connectivity loss or server rejection.
                // Surface the error and stop further processing so the user may retry.
                lastError = "File upload failed: \(error.localizedDescription)"
                return
            }
        }

        var expires: Date? = nil
        if expiresInMinutes > 0 {
            expires = Date().addingTimeInterval(expiresInMinutes * 60)
        }

        do {
            if let gid = selectedGroup {
                // Send to the selected group chat
                try await api.sendGroupMessage(input, groupId: gid, fileId: fileId, expiresAt: expires)
            } else {
                // Send a direct message
                try await api.sendMessage(input, to: recipient, fileId: fileId, expiresAt: expires)
            }
        } catch {
            // Message transmission may fail if the network is unreachable,
            // the server returns an error or the auth token expired.
            lastError = "Message send failed: \(error.localizedDescription)"
            return
        }

        // Optimistically append the sent message locally so the chat updates immediately.
        let msg = Message(
            id: Int(Date().timeIntervalSince1970),
            content: input,
            file_id: fileId,
            read: true,
            expires_at: expires,
            sender: nil,
            signature: nil
        )
        messages.append(msg)
        MessageStore.save(messages)
        input = ""
    }

    /// Persist cached messages and close the WebSocket connection.
    /// This should be called when the chat screen disappears so background
    /// tasks do not continue consuming resources.
    func disconnect() {
        // Tear down the socket and store the latest messages
        socket.disconnect()
        MessageStore.save(messages)
    }
}
