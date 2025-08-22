import Foundation

/*
 * WebSocketService.swift
 * ----------------------
 * Provides a small wrapper around ``URLSessionWebSocketTask`` that adds
 * automatic reconnection with exponential backoff.  The service publishes
 * connection state and received messages so SwiftUI views can react to
 * connectivity changes in real time.
 *
 * Design decisions:
 *   - Reconnection attempts are scheduled on a dedicated dispatch queue
 *     allowing tests to inject a controllable queue.
 *   - Exponential backoff starts at ``baseDelay`` and doubles up to
 *     ``maxDelay``.  This avoids hammering the server while still giving the
 *     user a chance to recover from transient failures.
 */
class WebSocketService: ObservableObject {
    /// Published state of the socket so the UI can display connection info.
    enum ConnectionStatus {
        case disconnected, connecting, connected
    }

    /// Underlying WebSocket task handling network I/O.
    private var task: URLSessionWebSocketTask?
    /// URLSession used for creating tasks.  Dependency injected for testing.
    private let session: URLSession
    /// Queue used for scheduling reconnection attempts.
    private let reconnectionQueue: DispatchQueue

    /// Messages received from the server are appended here for observers.
    @Published var messages: [Message] = []
    /// Current connection status published to the UI.
    @Published var status: ConnectionStatus = .disconnected

    /// Token used for authenticating; stored so reconnects can reuse it.
    private var authToken: String?
    /// Whether the service should continue trying to reconnect.
    private var shouldReconnect = false
    /// Work item representing a scheduled reconnect so it can be cancelled.
    private var pendingReconnect: DispatchWorkItem?
    /// Current retry attempt; influences the exponential backoff delay.
    private var retryCount = 0
    /// Initial delay before retrying after a failure.
    private let baseDelay: TimeInterval
    /// Maximum delay between retries to cap backoff growth.
    private let maxDelay: TimeInterval

    /// Create the service with an optional custom ``URLSession`` and timing
    /// parameters.  ``baseDelay`` and ``maxDelay`` default to sensible values
    /// but are tunable for tests.
    init(session: URLSession = .shared,
         baseDelay: TimeInterval = 1,
         maxDelay: TimeInterval = 60,
         reconnectionQueue: DispatchQueue = DispatchQueue.global()) {
        self.session = session
        self.baseDelay = baseDelay
        self.maxDelay = maxDelay
        self.reconnectionQueue = reconnectionQueue
    }

    /// Establish the WebSocket connection using ``token`` for authentication.
    /// On success ``status`` becomes ``.connected`` and message listening
    /// starts.  The token is stored so that reconnection attempts can reuse it.
    func connect(token: String) {
        authToken = token
        shouldReconnect = true
        createAndStartTask()
    }

    /// Actually create the socket task and begin listening.  Called for the
    /// initial connection and again for any automatic reconnections.
    private func createAndStartTask() {
        guard shouldReconnect, let token = authToken else { return }
        status = .connecting
        // WebSocketURL is defined in Info.plist and points to the backend.
        guard let urlString = Bundle.main.object(forInfoDictionaryKey: "WebSocketURL") as? String,
              let url = URL(string: urlString) else {
            status = .disconnected
            return
        }
        var request = URLRequest(url: url)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        // Create and start the WebSocket task
        task = session.webSocketTask(with: request)
        task?.resume()
        status = .connected
        retryCount = 0 // reset backoff after a successful connection
        // Begin listening for incoming messages
        listen()
    }

    /// Continuously receive messages from the socket and append them to
    /// ``messages``.  On failure a reconnection attempt is scheduled with
    /// exponential backoff.
    private func listen() {
        task?.receive { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .failure:
                // Connection closed or failed. Transition to disconnected and
                // trigger a reconnect if allowed.
                self.status = .disconnected
                self.scheduleReconnect()
            case .success(let message):
                if case .string(let text) = message,
                   let data = text.data(using: .utf8),
                   // Payload is a JSON object with ciphertext and optional group id.
                   let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let b64 = payload["content"] as? String {
                    var plaintext: String?
                    // Decrypt depending on whether this is a group message.
                    if let gid = payload["group_id"] as? Int, let ct = Data(base64Encoded: b64) {
                        plaintext = try? CryptoManager.decryptGroupMessage(ct, groupId: gid)
                    } else {
                        plaintext = try? CryptoManager.decryptRSA(b64)
                    }
                    if let plaintext = plaintext {
                        let fid = payload["file_id"] as? Int
                        let msgId = payload["id"] as? Int ?? Int(Date().timeIntervalSince1970)
                        let msg = Message(id: msgId, content: plaintext, file_id: fid, read: true)
                        DispatchQueue.main.async {
                            self.messages.append(msg)
                        }
                    }
                }
                // Continue listening for the next message.
                self.listen()
            }
        }
    }

    /// Schedule a reconnection attempt using exponential backoff.  The delay
    /// doubles with each failure up to ``maxDelay``.  If ``disconnect`` has
    /// been called no further attempts occur.
    private func scheduleReconnect() {
        guard shouldReconnect else { return }
        let delay = min(maxDelay, baseDelay * pow(2, Double(retryCount)))
        retryCount += 1
        let work = DispatchWorkItem { [weak self] in
            self?.createAndStartTask()
        }
        pendingReconnect = work
        reconnectionQueue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    /// Close the WebSocket connection and cancel any pending reconnect
    /// attempts.  This is typically invoked when the user logs out.
    func disconnect() {
        shouldReconnect = false
        pendingReconnect?.cancel()
        pendingReconnect = nil
        task?.cancel(with: .goingAway, reason: nil)
        status = .disconnected
    }
}
