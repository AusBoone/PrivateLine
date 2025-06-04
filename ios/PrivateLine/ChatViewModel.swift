import Foundation
import Combine

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var messages: [Message] = []
    @Published var input = ""
    @Published var recipient = "bob"

    private let api: APIService
    private let socket = WebSocketService()
    private var cancellables = Set<AnyCancellable>()

    init(api: APIService) {
        self.api = api
    }

    func load() async {
        // Load cached messages first for offline support
        messages = MessageStore.load()
        do {
            let fetched = try await api.fetchMessages()
            messages = fetched
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
            try await api.sendMessage(input, to: recipient)
            let msg = Message(id: Int(Date().timeIntervalSince1970), content: input)
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
