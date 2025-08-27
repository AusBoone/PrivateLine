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
 * - Initializer now accepts an optional ``WebSocketService`` so tests can
 *   inject a mock instance. The default path enforces secure WebSocket URLs
 *   via ``WebSocketService``'s throwing initializer.
 * - Introduced ``contacts`` list and ``fetchContacts()`` helper so the user
 *   picker reflects live data from the backend instead of hard-coded
 *   placeholders.
 * - Added ``isLoading`` state toggled around network operations so the UI can
 *   present progress indicators and disable interactions during lengthy tasks.
 * - Added ``fetchGroups()`` and ``selectConversation(...)`` helpers enabling
 *   the new ``ConversationListView`` to update available threads and refresh
 *   messages when the user switches chats.
 * - Tracked attachment filenames and introduced ``selectAttachment``/
 *   ``removeAttachment`` helpers so ``ChatView`` can preview and discard
 *   attachments prior to sending.
 * - Added ``scrollTarget`` published property tracking the identifier of the
 *   most recent message so ``ChatView`` can automatically scroll to the newest
 *   entry whenever history changes or a send completes.
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
    /// Available direct message contacts retrieved from the backend.
    /// Keeping this list up to date lets the picker in ``ChatView`` show
    /// only valid usernames.
    @Published var contacts: [String] = []
    /// Available chat groups pulled from the backend.
    @Published var groups: [Group] = []
    /// Identifier of the selected group chat if the user is chatting in a group.
    /// ``nil`` indicates a direct person-to-person conversation.
    @Published var selectedGroup: Int? = nil
    /// Binary data for an optional file attachment chosen by the user.
    @Published var attachment: Data? = nil
    /// Original filename for the selected attachment displayed in the preview.
    /// ``nil`` when no attachment has been picked or the filename is unknown.
    @Published var attachmentFilename: String? = nil
    /// Minutes after which newly sent messages should expire. ``0`` means no
    /// expiration and messages persist indefinitely.
    @Published var expiresInMinutes: Double = 0
    /// Human readable description of the most recent error. ``nil`` when the
    /// last operation succeeded. Views observe this value to surface alerts and
    /// suggest retry actions.
    @Published var lastError: String? = nil
    /// Flag indicating whether a network operation is currently executing.
    /// Views bind to this state to show ``ProgressView`` overlays and disable
    /// controls to prevent duplicate submissions.
    @Published var isLoading = false
    /// Identifier of the most recent message. Views observe this to auto-scroll
    /// to the bottom whenever a new message is added or history loads.
    @Published var scrollTarget: Int? = nil

    /// Backend API wrapper used for all network operations.
    let api: APIService
    /// WebSocket service providing real-time updates.
    private let socket: WebSocketService
    /// Subscriptions to updates from ``socket``.
    private var cancellables = Set<AnyCancellable>()

    /// Create a new view model using an ``APIService`` instance.
    /// - Parameter socket: Optional preconfigured ``WebSocketService``. Tests
    ///   inject a mock to avoid real network work. Production code defaults to
    ///   instantiating ``WebSocketService`` which enforces a secure ``wss``
    ///   endpoint and will crash early if misconfigured.
    init(api: APIService, socket: WebSocketService? = nil) {
        self.api = api
        if let provided = socket {
            // Allow tests to supply a stub without touching the network.
            self.socket = provided
        } else {
            // ``try!`` is acceptable here because configuration errors indicate
            // a developer mistake that should be fixed before shipping.
            self.socket = try! WebSocketService(api: api)
        }
    }

    /// Retrieve the list of contacts from the backend service.
    /// Errors are surfaced via ``lastError`` so the UI can display a
    /// user-friendly message while still attempting to load messages.
    /// - Note: The backend returns an array of usernames. ``contacts`` is
    ///   cleared on failure to avoid presenting stale results.
    func fetchContacts() async {
        do {
            // Ask the API for currently available direct message contacts.
            // ``APIService`` throws when the network request fails or the user
            // is unauthenticated.
            contacts = try await api.fetchContacts()
        } catch {
            // Propagate the error to observers and reset contacts to reflect
            // the absence of valid data.
            contacts = []
            lastError = "Contact fetch failed: \(error.localizedDescription)"
        }
    }

    /// Retrieve the list of chat groups the user belongs to.
    /// Errors are captured in ``lastError`` and the ``groups`` array is cleared
    /// on failure so the UI does not show stale data.
    func fetchGroups() async {
        do {
            // Ask the API for all group conversations available to the user.
            groups = try await api.fetchGroups()
        } catch {
            // Reset groups to reflect the lack of valid information and surface
            // the failure so the user can retry.
            groups = []
            lastError = "Group fetch failed: \(error.localizedDescription)"
        }
    }

    /// Store a newly selected attachment so the UI can show a preview.
    /// - Parameters:
    ///   - data: Raw file bytes selected by the user.
    ///   - filename: Original file name for display purposes.
    /// - Note: The file is not uploaded until ``send()`` is invoked. Users may
    ///   replace or remove the attachment before sending.
    func selectAttachment(data: Data, filename: String) {
        attachment = data
        attachmentFilename = filename
    }

    /// Remove any currently selected attachment. Called when the user taps the
    /// "Remove" button in ``ChatView``'s preview area. Both the binary data and
    /// stored filename are cleared so no stale information remains if a new
    /// attachment is chosen later.
    func removeAttachment() {
        attachment = nil
        attachmentFilename = nil
    }

    /// Update which conversation is active and load its message history.
    /// - Parameters:
    ///   - recipient: Username for a direct message thread. Provide ``nil`` when
    ///     selecting a group chat.
    ///   - groupID: Identifier for a group conversation. Provide ``nil`` when
    ///     selecting a direct message.
    func selectConversation(recipient: String? = nil, groupID: Int? = nil) async {
        if let gid = groupID {
            // Switching to a group chat overrides any direct recipient.
            selectedGroup = gid
        } else if let user = recipient {
            // Direct messages clear the group selection and set the recipient.
            selectedGroup = nil
            self.recipient = user
        }
        // Reload message history for the newly selected conversation.
        await load()
    }

    /// Fetch messages from the server and establish the WebSocket connection.
    /// Local cached messages are loaded first so the UI can display immediately
    /// while the network request is in flight.
    func load() async {
        // Indicate loading so the view can display a spinner and disable inputs.
        isLoading = true
        defer { isLoading = false } // Always reset regardless of path taken
        // Load cached messages first for offline support
        // Remove locally cached messages that have already expired
        let cached = MessageStore.load().filter { msg in
            guard let exp = msg.expires_at else { return true }
            return exp > Date()
        }
        messages = cached
        // Trigger an initial scroll to the latest cached message so the view
        // resumes at the bottom even when offline.
        scrollTarget = cached.last?.id
        // Refresh group metadata before loading messages so the conversation
        // list remains current even if message retrieval fails.
        await fetchGroups()
        do {
            // Fetch either direct or group conversation history depending on
            // the user's current selection.
            let fetched = try await (selectedGroup != nil ? api.fetchGroupMessages(selectedGroup!) : api.fetchMessages())
            let valid = fetched.filter { msg in
                guard let exp = msg.expires_at else { return true }
                return exp > Date()
            }
            messages = valid
            // Scroll to the newest fetched message so the latest history is visible.
            scrollTarget = valid.last?.id
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
                // Update scroll target so the UI auto-scrolls when a message arrives.
                self?.scrollTarget = valid.last?.id
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
        // Flag the send operation as loading to prevent duplicate taps.
        isLoading = true
        defer { isLoading = false } // Ensure the flag clears even on failure
        // Clear any previous error so the view reflects only the latest attempt.
        lastError = nil

        var fileId: Int? = nil
        if let data = attachment {
            do {
                // Upload attachment first so the returned id can be included
                // in the message body. Preserve the original filename when
                // possible so recipients see a meaningful label.
                let name = attachmentFilename ?? "file"
                fileId = try await api.uploadFile(data: data, filename: name)
                attachment = nil
                attachmentFilename = nil
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
        // Publish the new message id so the UI can scroll to it immediately.
        scrollTarget = msg.id
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
