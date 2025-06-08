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
    /// Identifier of the selected group chat, if any.
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
    func load() async {
        // Load cached messages first for offline support
        messages = MessageStore.load()
        do {
            groups = try await api.fetchGroups()
            let fetched = try await (selectedGroup != nil ? api.fetchGroupMessages(selectedGroup!) : api.fetchMessages())
            messages = fetched
            for msg in fetched where msg.read != true && (msg.id != 0) {
                try? await api.markMessageRead(id: msg.id)
            }
            MessageStore.save(fetched)
            if let token = api.authToken {
                socket.connect(token: token)
            }
            socket.$messages.sink { [weak self] msgs in
                self?.messages = msgs
                MessageStore.save(msgs)
            }.store(in: &cancellables)
        } catch {
            messages = []
        }
    }

    /// Encrypt and send the current input to the selected recipient or group.
    func send() async {
        do {
            var fileId: Int? = nil
            if let data = attachment {
                fileId = try await api.uploadFile(data: data, filename: "file")
                attachment = nil
            }
            if let gid = selectedGroup {
                try await api.sendGroupMessage(input, groupId: gid, fileId: fileId)
            } else {
                try await api.sendMessage(input, to: recipient, fileId: fileId)
            }
            let msg = Message(id: Int(Date().timeIntervalSince1970), content: input, file_id: fileId, read: true)
            messages.append(msg)
            MessageStore.save(messages)
            input = ""
        } catch {
            // ignore for now
        }
    }

    /// Persist cached messages and close the WebSocket connection.
    func disconnect() {
        socket.disconnect()
        MessageStore.save(messages)
    }
}
