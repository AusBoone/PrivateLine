import Foundation
import Crypto

/// Codable representation of a message received over the WebSocket.
///
/// The server delivers messages as JSON objects containing a number of
/// fields.  Using a strongly typed structure instead of ad‑hoc dictionary
/// parsing allows the decoder to enforce the presence of required properties
/// and provides compile‑time documentation for the expected schema.
struct SocketMessage: Codable {
    /// Base64 encoded ciphertext of the message body.
    let content: String
    /// Username of the sender.
    let sender: String
    /// Base64 encoded signature verifying ``content``.
    let signature: String
    /// SHA256 fingerprint of the sender's public key.
    let fingerprint: String
    /// Identifier of the group the message belongs to, ``nil`` for direct chats.
    let group_id: Int?
    /// Optional server generated identifier for the message.
    let id: Int?
    /// Optional identifier referencing an attached file.
    let file_id: Int?
}

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
 *     networking stack. Pinning now compares the SHA-256 fingerprint of the
 *     certificate's SubjectPublicKeyInfo allowing multiple pins for smoother
 *     rotations.
 * - Enforces that the WebSocket endpoint uses ``wss``. The initializer throws
 *   when an insecure ``ws`` URL is supplied or missing, preventing the service
 *   from establishing plaintext connections.
 * - 2025 update: replaces dictionary-based parsing with ``SocketMessage`` and
 *   ``JSONDecoder`` while enforcing a maximum payload size to drop malformed or
 *   overly large frames early.
*/
class WebSocketService: ObservableObject {
    /// Maximum size for a single text frame in bytes. Messages larger than this
    /// are discarded to protect the client from memory exhaustion attacks.
    static let maxPayloadBytes = 64 * 1024
    /// Errors describing configuration issues like missing or insecure URLs.
    enum ConfigurationError: LocalizedError {
        /// Triggered when the URL uses ``ws`` instead of ``wss``.
        case insecureScheme(String)
        /// Triggered when the Info.plist lacks ``WebSocketURL``.
        case missingURL(String)

        var errorDescription: String? {
            switch self {
            case .insecureScheme(let url):
                return "Insecure URL scheme detected: \(url). Use wss."
            case .missingURL(let key):
                return "Missing configuration value for \(key)."
            }
        }
    }
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
    /// Endpoint for the WebSocket connection. Validated to use ``wss``.
    private let socketURL: URL

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
         url: URL? = nil,
         session: URLSession? = nil,
         baseDelay: TimeInterval = 1,
         maxDelay: TimeInterval = 60,
         reconnectionQueue: DispatchQueue = DispatchQueue.global()) throws {
        self.api = api

        // Resolve the WebSocket endpoint from either the provided parameter or
        // the app's Info.plist. Reject non-``wss`` schemes to avoid insecure
        // connections.
        if let supplied = url {
            guard supplied.scheme == "wss" else {
                throw ConfigurationError.insecureScheme(supplied.absoluteString)
            }
            self.socketURL = supplied
        } else if let urlString = Bundle.main.object(forInfoDictionaryKey: "WebSocketURL") as? String,
                  let wsURL = URL(string: urlString) {
            guard wsURL.scheme == "wss" else {
                throw ConfigurationError.insecureScheme(wsURL.absoluteString)
            }
            self.socketURL = wsURL
        } else {
            throw ConfigurationError.missingURL("WebSocketURL")
        }

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
        // Use the previously validated secure endpoint.
        var request = URLRequest(url: socketURL)
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
                   let data = text.data(using: .utf8) {
                    // Reject messages that exceed the configured size limit to
                    // guard against memory exhaustion.
                    guard data.count <= WebSocketService.maxPayloadBytes else {
                        self.listen()
                        return
                    }

                    // Decode the JSON payload into ``SocketMessage``. Missing
                    // or malformed fields cause the message to be ignored.
                    let decoder = JSONDecoder()
                    if let socketMessage = try? decoder.decode(SocketMessage.self, from: data),
                       !socketMessage.content.isEmpty,
                       !socketMessage.sender.isEmpty,
                       !socketMessage.signature.isEmpty,
                       !socketMessage.fingerprint.isEmpty,
                       let sig = Data(base64Encoded: socketMessage.signature) {
                        Task {
                            do {
                                let keyPem = try await self.api.publicKey(for: socketMessage.sender)
                                guard CryptoManager.fingerprint(of: keyPem) == socketMessage.fingerprint else { return }
                                guard CryptoManager.verifySignature(socketMessage.content, signature: sig, publicKeyPem: keyPem) else { return }

                                var plaintext: String?
                                if let gid = socketMessage.group_id,
                                   let ct = Data(base64Encoded: socketMessage.content) {
                                    plaintext = try? CryptoManager.decryptGroupMessage(ct, groupId: gid)
                                } else {
                                    plaintext = try? CryptoManager.decryptRSA(socketMessage.content)
                                }

                                if let plaintext = plaintext {
                                    let msg = Message(
                                        id: socketMessage.id ?? Int(Date().timeIntervalSince1970),
                                        content: plaintext,
                                        file_id: socketMessage.file_id,
                                        read: true,
                                        expires_at: nil,
                                        sender: socketMessage.sender,
                                        signature: socketMessage.signature
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
    /// and WebSocket traffic are validated against the bundled SPKI fingerprints
    /// stored in ``server_fingerprints.txt``. Any mismatch cancels the handshake
    /// and notifies listeners so the UI can surface the problem.
    private class PinningDelegate: NSObject, URLSessionDelegate {
        /// SPKI fingerprints considered valid for the connection.
        private let validFingerprints: Set<String>

        override init() {
            if let url = Bundle.main.url(forResource: "server_fingerprints", withExtension: "txt"),
               let contents = try? String(contentsOf: url) {
                let lines = contents.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
                validFingerprints = Set(lines.filter { !$0.isEmpty })
            } else {
                validFingerprints = []
            }
        }

        /// Compare the server certificate's SPKI fingerprint against the pinned
        /// set and accept or reject the connection accordingly.
        func urlSession(_ session: URLSession,
                        didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard let trust = challenge.protectionSpace.serverTrust,
                  let serverCert = SecTrustGetCertificateAtIndex(trust, 0),
                  let fingerprint = PinningDelegate.fingerprint(for: serverCert) else {
                completionHandler(.performDefaultHandling, nil)
                return
            }

            if validFingerprints.contains(fingerprint) {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                NotificationCenter.default.post(name: APIService.pinningFailureNotification, object: nil)
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }

        /// Compute the SPKI SHA-256 fingerprint for ``cert``.
        private static func fingerprint(for cert: SecCertificate) -> String? {
            guard let key = SecCertificateCopyKey(cert),
                  let keyData = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
                return nil
            }
            let algId: [UInt8] = [0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00]
            let bitString: [UInt8] = [0x03] + derLength(of: keyData.count + 1) + [0x00] + [UInt8](keyData)
            let spki = Data([0x30] + derLength(of: algId.count + bitString.count) + algId + bitString)
            let digest = SHA256.hash(data: spki)
            return Data(digest).base64EncodedString()
        }

        /// Encode ``length`` using DER rules.
        private static func derLength(of length: Int) -> [UInt8] {
            if length < 128 { return [UInt8(length)] }
            var len = length
            var bytes: [UInt8] = []
            while len > 0 {
                bytes.insert(UInt8(len & 0xff), at: 0)
                len >>= 8
            }
            return [0x80 | UInt8(bytes.count)] + bytes
        }
    }
}
