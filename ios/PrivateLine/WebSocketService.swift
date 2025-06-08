import Foundation

/// Handles real-time message updates using URLSession WebSocket.
class WebSocketService: ObservableObject {
    /// Underlying WebSocket task.
    private var task: URLSessionWebSocketTask?
    /// URLSession used for creating the task. Injectable for testing.
    private let session: URLSession
    /// Messages received from the server.
    @Published var messages: [Message] = []

    /// Create the service with an optional custom ``URLSession``.
    init(session: URLSession = .shared) {
        self.session = session
    }

    /// Establish the WebSocket connection using ``token`` for authentication.
    func connect(token: String) {
        guard let urlString = Bundle.main.object(forInfoDictionaryKey: "WebSocketURL") as? String,
              let url = URL(string: urlString) else { return }
        var request = URLRequest(url: url)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        // Create and start the WebSocket task
        task = session.webSocketTask(with: request)
        task?.resume()
        // Begin listening for incoming messages
        listen()
    }

    /// Continuously receive messages from the socket and append them to ``messages``.
    private func listen() {
        task?.receive { [weak self] result in
            switch result {
            case .failure:
                break
            case .success(let message):
                if case .string(let text) = message,
                   let data = text.data(using: .utf8),
                   let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let b64 = payload["content"] as? String {
                    var plaintext: String?
                    // Decrypt depending on whether this is a group message
                    if let gid = payload["group_id"] as? Int, let ct = Data(base64Encoded: b64) {
                        plaintext = try? CryptoManager.decryptGroupMessage(ct, groupId: gid)
                    } else {
                        plaintext = try? CryptoManager.decryptRSA(b64)
                    }
                    if let plaintext = plaintext {
                        let fid = payload["file_id"] as? Int
                        let msg = Message(id: Int(Date().timeIntervalSince1970), content: plaintext, file_id: fid)
                        DispatchQueue.main.async {
                            self?.messages.append(msg)
                        }
                    }
                }
            }
            // Continue listening for the next message
            self?.listen()
        }
    }

    /// Close the WebSocket connection.
    func disconnect() {
        task?.cancel(with: .goingAway, reason: nil)
    }
}
