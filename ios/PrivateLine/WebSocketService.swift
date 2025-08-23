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
 *   - Uses a dedicated ``URLSession`` with certificate pinning to mirror the
 *     security of ``APIService``. This guards WebSocket traffic against
 *     man-in-the-middle attacks and keeps behaviour consistent across the
 *     networking stack.
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
    /// API client used to fetch public keys for signature verification.
    private let api: APIService
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
    ///
    /// - Parameters:
    ///   - session: Optional ``URLSession`` to use. When ``nil`` a new session
    ///     with certificate pinning is created to guard against MITM attacks.
    ///   - baseDelay: Starting delay for reconnection backoff.
    ///   - maxDelay: Maximum delay allowed for reconnection backoff.
    ///   - reconnectionQueue: Queue on which reconnect attempts are scheduled.
    init(api: APIService,
         session: URLSession? = nil,
         baseDelay: TimeInterval = 1,
         maxDelay: TimeInterval = 60,
         reconnectionQueue: DispatchQueue = DispatchQueue.global()) {
        self.api = api
        if let provided = session {
            // Tests may inject a mock session to avoid real network calls.
            self.session = provided
        } else {
            let config = URLSessionConfiguration.default
            // Use a dedicated session with certificate pinning to mirror
            // ``APIService.PinningDelegate`` and avoid ``URLSession.shared``.
            self.session = URLSession(configuration: config,
                                     delegate: PinningDelegate(),
                                     delegateQueue: nil)
        }
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
                   let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let b64 = payload["content"] as? String,
                   let sender = payload["sender"] as? String,
                   let sigB64 = payload["signature"] as? String,
                   let sig = Data(base64Encoded: sigB64),
                   let fingerprint = payload["fingerprint"] as? String {
                    Task {
                        do {
                            let keyPem = try await self.api.publicKey(for: sender)
                            guard CryptoManager.fingerprint(of: keyPem) == fingerprint else { return }
                            guard CryptoManager.verifySignature(b64, signature: sig, publicKeyPem: keyPem) else { return }
                            var plaintext: String?
                            if let gid = payload["group_id"] as? Int, let ct = Data(base64Encoded: b64) {
                                plaintext = try? CryptoManager.decryptGroupMessage(ct, groupId: gid)
                            } else {
                                plaintext = try? CryptoManager.decryptRSA(b64)
                            }
                            if let plaintext = plaintext {
                                let fid = payload["file_id"] as? Int
                                let msgId = payload["id"] as? Int ?? Int(Date().timeIntervalSince1970)
                                let msg = Message(
                                    id: msgId,
                                    content: plaintext,
                                    file_id: fid,
                                    read: true,
                                    expires_at: nil,
                                    sender: sender,
                                    signature: sigB64
                                )
                                DispatchQueue.main.async {
                                    self.messages.append(msg)
                                }
                            }
                        } catch {
                            // Ignore malformed messages; listen continues below.
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

    /// Delegate enforcing certificate pinning for WebSocket connections.
    /// Mirrors the logic used by ``APIService.PinningDelegate`` so both HTTP
    /// and WebSocket traffic are validated against the bundled ``server.cer``
    /// certificate. Any mismatch cancels the handshake and notifies
    /// listeners so the UI can surface the problem.
    private class PinningDelegate: NSObject, URLSessionDelegate {
        func urlSession(_ session: URLSession,
                        didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            // Extract the certificate from the challenge and compare against the
            // bundled pinned certificate. If anything fails we fall back to the
            // system's default handling which typically rejects the connection.
            guard let trust = challenge.protectionSpace.serverTrust,
                  let serverCert = SecTrustGetCertificateAtIndex(trust, 0),
                  let pinnedURL = Bundle.main.url(forResource: "server", withExtension: "cer"),
                  let pinnedData = try? Data(contentsOf: pinnedURL),
                  let pinnedCert = SecCertificateCreateWithData(nil, pinnedData as CFData) else {
                completionHandler(.performDefaultHandling, nil)
                return
            }

            // Compare DER-encoded certificate data to ensure an exact match.
            let serverData = SecCertificateCopyData(serverCert) as Data
            let pinnedCertData = SecCertificateCopyData(pinnedCert) as Data
            if serverData == pinnedCertData {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                // Notify the rest of the app just like the API service does so
                // the UI can prompt the user to update their pinned cert.
                NotificationCenter.default.post(name: APIService.pinningFailureNotification, object: nil)
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
    }
}
