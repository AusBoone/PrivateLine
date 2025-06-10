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

    /// Backend API wrapper used for all network operations.
    let api: APIService
    /// WebSocket service providing real-time updates.
    private let socket = WebSocketService()
    /// Subscriptions to updates from ``socket``.
    private var cancellables = Set<AnyCancellable>()

    /// Create a new view model using an ``APIService`` instance.
    init(api: APIService) {
        self.api = api
    }

    /// Fetch messages from the server and establish the WebSocket connection.
    /// Local cached messages are loaded first so the UI can display immediately
    /// while the network request is in flight.
    func load() async {
        // Load cached messages first for offline support
        messages = MessageStore.load()
        do {
            // Retrieve available chat groups
            groups = try await api.fetchGroups()
            // Fetch either direct or group conversation history
            let fetched = try await (selectedGroup != nil ? api.fetchGroupMessages(selectedGroup!) : api.fetchMessages())
            messages = fetched
            // Mark unread messages as read on the server
            for msg in fetched where msg.read != true && (msg.id != 0) {
                try? await api.markMessageRead(id: msg.id)
            }
            // Persist the updated history locally
            MessageStore.save(fetched)
            // Establish WebSocket connection for real-time updates
            if let token = api.authToken {
                socket.connect(token: token)
            }
            // Update local messages whenever new ones arrive
            socket.$messages.sink { [weak self] msgs in
                self?.messages = msgs
                MessageStore.save(msgs)
            }.store(in: &cancellables)
        } catch {
            messages = []
        }
    }

    /// Encrypt and send the current input to the selected recipient or group.
    /// Attachments are uploaded first and the returned file id included in the
    /// message body. On success the plaintext is appended locally so the UI
    /// feels responsive while waiting for the server.
    func send() async {
        do {
            var fileId: Int? = nil
            if let data = attachment {
                // Upload attachment first so the returned id can be included
                fileId = try await api.uploadFile(data: data, filename: "file")
                attachment = nil
            }
            if let gid = selectedGroup {
                // Send to the selected group chat
                try await api.sendGroupMessage(input, groupId: gid, fileId: fileId)
            } else {
                // Send a direct message
                try await api.sendMessage(input, to: recipient, fileId: fileId)
            }
            // Optimistically append the sent message locally
            let msg = Message(id: Int(Date().timeIntervalSince1970), content: input, file_id: fileId, read: true)
            messages.append(msg)
            MessageStore.save(messages)
            input = ""
        } catch {
            // Ignore transmission errors for the demo app
        }
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
