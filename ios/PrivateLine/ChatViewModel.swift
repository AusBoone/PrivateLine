import Foundation
import Combine

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var messages: [Message] = []
    @Published var input = ""
    @Published var recipient = "bob"
    @Published var groups: [Group] = []
    @Published var selectedGroup: Int? = nil
    @Published var attachment: Data? = nil

    let api: APIService
    private let socket = WebSocketService()
    private var cancellables = Set<AnyCancellable>()

    init(api: APIService) {
        self.api = api
    }

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

    func send() async {
        do {
            var fileId: Int? = nil
            if let data = attachment {
                fileId = try await api.uploadFile(data: data, filename: "file")
                attachment = nil
            }
            if let gid = selectedGroup {
                try await api.sendGroupMessage(input, groupId: gid)
            } else {
                try await api.sendMessage(input, to: recipient)
            }
            let msg = Message(id: Int(Date().timeIntervalSince1970), content: input, file_id: fileId, read: true)
            messages.append(msg)
            MessageStore.save(messages)
            input = ""
        } catch {
            // ignore for now
        }
    }

    func disconnect() {
        socket.disconnect()
        MessageStore.save(messages)
    }
}
