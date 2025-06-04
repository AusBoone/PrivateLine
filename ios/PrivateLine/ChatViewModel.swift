import Foundation

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var messages: [Message] = []
    @Published var input = ""

    private let api: APIService
    private let socket = WebSocketService()

    init(api: APIService) {
        self.api = api
    }

    func load() async {
        do {
            messages = try await api.fetchMessages()
            if let token = api.authToken {
                socket.connect(token: token)
            }
            socket.$messages.assign(to: &$messages)
        } catch {
            messages = []
        }
    }

    func send() async {
        do {
            let msg = try await api.sendMessage(input)
            messages.append(msg)
            input = ""
        } catch {
            // ignore for now
        }
    }

    func disconnect() {
        socket.disconnect()
    }
}
