import Foundation

/// Handles real-time message updates using URLSession WebSocket.
class WebSocketService: ObservableObject {
    private var task: URLSessionWebSocketTask?
    private let session: URLSession
    @Published var messages: [Message] = []

    init(session: URLSession = .shared) {
        self.session = session
    }

    func connect(token: String) {
        guard let urlString = Bundle.main.object(forInfoDictionaryKey: "WebSocketURL") as? String,
              let url = URL(string: urlString) else { return }
        var request = URLRequest(url: url)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        task = session.webSocketTask(with: request)
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
                   let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let b64 = payload["content"] as? String,
                   let plaintext = try? CryptoManager.decryptRSA(b64) {
                    let msg = Message(id: Int(Date().timeIntervalSince1970), content: plaintext)
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
