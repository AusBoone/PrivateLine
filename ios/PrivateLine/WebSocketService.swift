import Foundation

/// Handles real-time message updates using URLSession WebSocket.
class WebSocketService: ObservableObject {
    private var task: URLSessionWebSocketTask?
    @Published var messages: [Message] = []

    func connect(token: String) {
        guard let urlString = Bundle.main.object(forInfoDictionaryKey: "WebSocketURL") as? String,
              let url = URL(string: urlString) else { return }
        var request = URLRequest(url: url)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        task = URLSession.shared.webSocketTask(with: request)
        task?.resume()
        listen()
    }

    private func listen() {
        task?.receive { [weak self] result in
            switch result {
            case .failure:
                break
            case .success(let message):
                if case .string(let text) = message,
                   let data = text.data(using: .utf8),
                   let msg = try? JSONDecoder().decode(Message.self, from: data) {
                    DispatchQueue.main.async {
                        self?.messages.append(msg)
                    }
                }
            }
            self?.listen()
        }
    }

    func disconnect() {
        task?.cancel(with: .goingAway, reason: nil)
    }
}
