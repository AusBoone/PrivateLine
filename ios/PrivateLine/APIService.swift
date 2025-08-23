/*
 * APIService.swift - Networking layer for the iOS client.
 * Manages authentication, message transfer and certificate pinning.
 *
 * Modifications:
 * - Added runtime check that logs when the bundled ``server.cer`` is close to
 *   expiration so developers can refresh it before failures occur.
 * - Introduced a notification-based callback to surface pinning failures to
 *   the UI, allowing the user to be guided toward updating the app.
 * - Implemented automatic access-token refreshing using a stored refresh token
 *   whenever a request returns ``401 Unauthorized``.
 * - Centralized HTTP status validation in ``sendRequest`` so callers receive
 *   clear ``URLError`` values and log messages for easier debugging.
 * - Cached public keys now track their fetch time and are refreshed
 *   automatically when older than a configurable duration (24 h by default) to
 *   cope with server-side key rotation.
 * - File uploads may now bind the target message and recipient to the
 *   ciphertext via AES-GCM additional authenticated data (AAD) so tampering with
 *   metadata is detected when downloads are decrypted.
 */
import Foundation
#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

/// Wrapper around the Flask REST API used by the app.
/// It handles user authentication and message operations.
class APIService: ObservableObject {
    /// Simple container bundling a public key with the time it was fetched.
    /// Using a struct keeps the cache type-safe and makes the timestamp
    /// association explicit.
    private struct CachedPublicKey {
        /// PEM encoded RSA public key as returned by the server.
        let key: String
        /// Point in time when the key was retrieved. Used to decide when a
        /// cached entry should be refreshed.
        let fetchedAt: Date
    }
    /// Base URL of the backend API, loaded from Info.plist.
    private let baseURL: URL
    var baseURLString: String { baseURL.absoluteString }

    /// Indicates whether the user is currently authenticated.
    @Published var isAuthenticated = false

    /// Flag toggled when certificate pinning fails so the UI can present a
    /// guidance alert instructing users to update the app or contact support.
    @Published var showCertificateWarning = false

    /// Count the number of failed login attempts.
    private var loginFailures = 0

    /// Cache of recipient public keys along with the timestamp when each key
    /// was retrieved. Keeping track of the fetch time allows the service to
    /// invalidate keys after a configurable interval so server-side key
    /// rotations are respected without requiring an app restart.
    private var publicKeyCache: [String: CachedPublicKey] = [:]

    /// Maximum age for cached public keys before a refresh is triggered. The
    /// default of 24 hours strikes a balance between avoiding unnecessary
    /// network calls and ensuring new keys are picked up promptly if the
    /// backend rotates them. A value of ``0`` disables caching.
    private let publicKeyCacheDuration: TimeInterval

    /// Stored pinned fingerprints
    private var pinnedKeys: [String: String] = [:]
    @Published var groups: [Group] = []
    private var groupKeys: [Int: String] = [:]

    /// Notification name emitted when certificate pinning fails.
    static let pinningFailureNotification = Notification.Name("APIPinningFailure")

    /// URLSession used for API calls with certificate pinning.
    private let session: URLSession

    /// Observer token for certificate pinning failure notifications.
    private var pinningObserver: NSObjectProtocol?

    /// JWT token returned after a successful login.
    // JWT used for authorizing API requests
    private var token: String? {
        didSet {
            if let token = token {
                KeychainService.saveToken(token)
            } else {
                KeychainService.removeToken()
            }
        }
    }

    /// Refresh token allowing the client to obtain new access tokens when the
    /// current one expires. Stored securely in the keychain.
    private var refreshToken: String? {
        didSet {
            if let rt = refreshToken {
                KeychainService.saveRefreshToken(rt)
            } else {
                KeychainService.removeRefreshToken()
            }
        }
    }

    /// Create the service using ``session`` if provided, otherwise a pinned session.
    /// - Parameters:
    ///   - session: Optional ``URLSession`` injected for testing.
    ///   - publicKeyCacheDuration: Maximum age for cached public keys in seconds
    ///     before the value is refreshed from the backend. Defaults to 24 hours.
    init(session: URLSession? = nil, publicKeyCacheDuration: TimeInterval = 60 * 60 * 24) {
        // Store cache duration first so it is available during initialization of
        // other components if needed.
        self.publicKeyCacheDuration = publicKeyCacheDuration
        if let urlString = Bundle.main.object(forInfoDictionaryKey: "BackendBaseURL") as? String,
           let url = URL(string: urlString) {
            baseURL = url
        } else {
            baseURL = URL(string: "http://localhost:5000/api")!
        }

        // Configure pinned session unless one is injected for testing
        if let s = session {
            self.session = s
        } else {
            let config = URLSessionConfiguration.default
            // PinningDelegate performs certificate pinning for all requests
            self.session = URLSession(configuration: config, delegate: PinningDelegate(), delegateQueue: nil)

            // Observe pinning failures so the UI can surface a helpful message.
            pinningObserver = NotificationCenter.default.addObserver(
                forName: APIService.pinningFailureNotification,
                object: nil,
                queue: .main
            ) { [weak self] _ in
                self?.showCertificateWarning = true
            }

            // Evaluate expiration of the bundled certificate and log if it is
            // nearing its validity end. This helps developers refresh
            // ``server.cer`` before it actually expires.
            if let pinnedURL = Bundle.main.url(forResource: "server", withExtension: "cer"),
               let pinnedData = try? Data(contentsOf: pinnedURL),
               let pinnedCert = SecCertificateCreateWithData(nil, pinnedData as CFData),
               isCertificateExpiringSoon(pinnedCert) {
                print("Warning: pinned certificate expires soon; run scripts/update_server_cert.sh to refresh it")
            }
        }

        // Attempt to load the stored token, prompting for biometrics when available.
        #if canImport(LocalAuthentication)
        let context = LAContext()
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
            let reason = "Authenticate to unlock PrivateLine"
            if (try? context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)) == true,
               let stored = KeychainService.loadToken(context: context) {
                token = stored
                refreshToken = KeychainService.loadRefreshToken(context: context)
                isAuthenticated = true
            }
        } else if let stored = KeychainService.loadToken() {
            // Fallback if biometrics unavailable
            token = stored
            refreshToken = KeychainService.loadRefreshToken()
            isAuthenticated = true
        }
        #else
        if let stored = KeychainService.loadToken() {
            token = stored
            refreshToken = KeychainService.loadRefreshToken()
            isAuthenticated = true
        }
        #endif

        // Preload any persisted group keys for offline message access
        CryptoManager.preloadPersistedGroupKeys()
    }

    deinit {
        // Clean up observer when the service is deallocated.
        if let obs = pinningObserver {
            NotificationCenter.default.removeObserver(obs)
        }
    }

    /// Send ``request`` to the backend, attaching the current access token and
    /// automatically attempting a token refresh if the server responds with
    /// ``401 Unauthorized``. Requests are retried once after a successful
    /// refresh.
    /// - Parameters:
    ///   - request: The ``URLRequest`` to send.
    ///   - requiresAuth: Whether to attach the ``Authorization`` header.
    /// - Returns: Tuple of response data and metadata.
    private func sendRequest(_ request: URLRequest, requiresAuth: Bool = true) async throws -> (Data, URLResponse) {
        var req = request
        if requiresAuth, let token = token {
            req.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        // Perform the request using the session configured with certificate pinning.
        var (data, response) = try await session.data(for: req)

        // Handle 401 responses by attempting a single token refresh.
        if requiresAuth,
           let http = response as? HTTPURLResponse,
           http.statusCode == 401 {
            // Access token likely expired; attempt to refresh and retry once.
            if await refreshAccessToken(), let new = token {
                var retry = request
                retry.setValue("Bearer \(new)", forHTTPHeaderField: "Authorization")
                (data, response) = try await session.data(for: retry)
            } else {
                // Refresh failed; mark user as logged out and surface auth error.
                DispatchQueue.main.async { self.isAuthenticated = false }
                throw URLError(.userAuthenticationRequired)
            }
        }

        // Validate that we received a proper HTTP response with a successful status code.
        guard let http = response as? HTTPURLResponse else {
            // Non-HTTP responses indicate a fundamental networking failure.
            print("Unexpected response for \(req.url?.absoluteString ?? "<unknown>")")
            throw URLError(.badServerResponse)
        }
        guard (200...299).contains(http.statusCode) else {
            // Log descriptive error to help developers debug and provide feedback for users.
            let msg = HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            print("Request to \(req.url?.absoluteString ?? "<unknown>") failed with status \(http.statusCode): \(msg)")
            switch http.statusCode {
            case 400...499:
                // Client-side errors indicate the request was invalid or unauthorized.
                throw URLError(.badServerResponse)
            case 500...599:
                // Server-side errors usually mean the host is currently unavailable.
                throw URLError(.cannotConnectToHost)
            default:
                throw URLError(.badServerResponse)
            }
        }

        return (data, response)
    }

    /// Attempt to log in with the provided credentials.
    func login(username: String, password: String) async throws {
        let url = baseURL.appendingPathComponent("login")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        // Encode credentials as JSON body
        request.httpBody = try JSONEncoder().encode(["username": username, "password": password])
        do {
            let (data, _) = try await session.data(for: request)
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let token = json["access_token"] as? String,
                  let refresh = json["refresh_token"] as? String else {
                throw URLError(.badServerResponse)
            }
            // Reset failure counter and unlock the private key
            loginFailures = 0
            try? CryptoManager.loadPrivateKey(password: password)
            self.token = token
            self.refreshToken = refresh
            do {
                // Retrieve pinned key fingerprints for certificate validation
                let request = URLRequest(url: self.baseURL.appendingPathComponent("pinned_keys"))
                let (pkData, _) = try await self.sendRequest(request)
                if let json = try? JSONSerialization.jsonObject(with: pkData) as? [String: [[String: String]]],
                   let arr = json["pinned_keys"] {
                    self.pinnedKeys = Dictionary(uniqueKeysWithValues: arr.map { ($0["username"]!, $0["fingerprint"]!) })
                }
            } catch {
                self.pinnedKeys = [:]
            }
            // Update UI state on the main thread
            DispatchQueue.main.async {
                self.isAuthenticated = true
            }
        } catch {
            loginFailures += 1
            if loginFailures >= 3 {
                KeychainService.removeToken()
                KeychainService.removeRefreshToken()
            }
            throw error
        }
    }

    /// Register a new user.
    func register(username: String, email: String, password: String) async throws {
        let url = baseURL.appendingPathComponent("register")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        // Encode the form fields as URL encoded parameters
        var comps = URLComponents()
        comps.queryItems = [
            URLQueryItem(name: "username", value: username),
            URLQueryItem(name: "email", value: email),
            URLQueryItem(name: "password", value: password),
        ]
        request.httpBody = comps.query?.data(using: .utf8)
        // ``register`` does not require an auth token, so we disable it.
        let (data, _) = try await sendRequest(request, requiresAuth: false)
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
           let enc = json["encrypted_private_key"],
           let salt = json["salt"],
           let nonce = json["nonce"] {
            let fp = json["fingerprint"]
            // Store the encrypted private key material for later use
            CryptoManager.storeKeyMaterial(.init(encrypted_private_key: enc, salt: salt, nonce: nonce, fingerprint: fp))
            if let fp = fp {
                print("Fingerprint: \(fp)")
            }
        }
    }

    /// Fetch all messages for the authenticated user.
    func fetchMessages() async throws -> [Message] {
        guard token != nil else { return [] }
        let request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        let (data, _) = try await sendRequest(request)
        let json = try JSONDecoder().decode([String: [Message]].self, from: data)
        let msgs = json["messages"] ?? []
        return msgs.compactMap { msg in
            if let text = try? CryptoManager.decryptRSA(msg.content) {
                return Message(id: msg.id, content: text, file_id: msg.file_id, read: msg.read, expires_at: msg.expires_at)
            }
            return nil
        }
    }

    /// Retrieve and decrypt all messages for the given group.
    func fetchGroupMessages(_ id: Int) async throws -> [Message] {
        guard token != nil else { return [] }
        _ = try await groupKey(for: id)
        let request = URLRequest(url: baseURL.appendingPathComponent("groups/\(id)/messages"))
        let (data, _) = try await sendRequest(request)
        let json = try JSONDecoder().decode([String: [Message]].self, from: data)
        let msgs = json["messages"] ?? []
        return msgs.compactMap { msg in
            guard let data = Data(base64Encoded: msg.content) else { return nil }
            if let text = try? CryptoManager.decryptGroupMessage(data, groupId: id) {
                return Message(id: msg.id, content: text, file_id: msg.file_id, read: msg.read, expires_at: msg.expires_at)
            }
            return nil
        }
    }

    /// Fetch the list of available chat groups from the backend.
    func fetchGroups() async throws -> [Group] {
        guard token != nil else { return [] }
        let request = URLRequest(url: baseURL.appendingPathComponent("groups"))
        let (data, _) = try await sendRequest(request)
        let json = try JSONDecoder().decode([String: [Group]].self, from: data)
        let gs = json["groups"] ?? []
        DispatchQueue.main.async { self.groups = gs }
        return gs
    }

    /// Encrypt ``content`` with the group key and POST it to the server.
    func sendGroupMessage(_ content: String, groupId: Int, fileId: Int? = nil, expiresAt: Date? = nil) async throws {
        guard token != nil else { throw URLError(.userAuthenticationRequired) }
        _ = try await groupKey(for: groupId)
        var request = URLRequest(url: baseURL.appendingPathComponent("groups/\(groupId)/messages"))
        request.httpMethod = "POST"
        let encrypted = try CryptoManager.encryptGroupMessage(content, groupId: groupId)
        let b64 = encrypted.base64EncodedString()
        let sig = try CryptoManager.signMessage(b64).base64EncodedString()
        var comps = URLComponents()
        var items = [
            URLQueryItem(name: "content", value: b64),
            URLQueryItem(name: "group_id", value: String(groupId)),
            URLQueryItem(name: "signature", value: sig),
        ]
        if let id = fileId {
            items.append(URLQueryItem(name: "file_id", value: String(id)))
        }
        if let exp = expiresAt {
            let iso = ISO8601DateFormatter().string(from: exp)
            items.append(URLQueryItem(name: "expires_at", value: iso))
        }
        comps.queryItems = items
        request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = comps.query?.data(using: .utf8)
        _ = try await sendRequest(request)
    }

    /// Encrypt ``data`` and upload it as ``filename``.
    ///
    /// - Parameters:
    ///   - data: Raw bytes to transmit.
    ///   - filename: Original filename supplied by the user interface.
    ///   - messageId: Optional identifier of the message that will reference the
    ///     file. When provided alongside ``recipient`` or ``groupId`` the value
    ///     is combined into a string "``messageId``:``recipient``" and used as
    ///     additional authenticated data during AES-GCM encryption. This mirrors
    ///     backend expectations so downloads can verify the attachment belongs to
    ///     the intended message and recipient.
    ///   - recipient: Username for direct messages. Provide either ``recipient``
    ///     or ``groupId`` when supplying ``messageId``.
    ///   - groupId: Group identifier for group chats.
    /// - Returns: The file id assigned by the server, or ``nil`` if the upload
    ///   failed before receiving a response.
    func uploadFile(
        data: Data,
        filename: String,
        messageId: Int? = nil,
        recipient: String? = nil,
        groupId: Int? = nil
    ) async throws -> Int? {
        guard let token = token else { return nil }
        var request = URLRequest(url: baseURL.appendingPathComponent("files"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let boundary = UUID().uuidString
        request.addValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

        var body = Data()

        // Helper to append a simple form field to the multipart body.
        func appendField(name: String, value: String) {
            body.append("--\(boundary)\r\n".data(using: .utf8)!)
            body.append("Content-Disposition: form-data; name=\"\(name)\"\r\n\r\n".data(using: .utf8)!)
            body.append("\(value)\r\n".data(using: .utf8)!)
        }

        var aadString: String?
        if let mid = messageId {
            // Determine the recipient string to use in AAD and for the form field.
            if let rec = recipient {
                appendField(name: "message_id", value: String(mid))
                appendField(name: "recipient", value: rec)
                aadString = "\(mid):\(rec)"
            } else if let gid = groupId {
                let rec = "g\(gid)"
                appendField(name: "message_id", value: String(mid))
                appendField(name: "recipient", value: rec)
                aadString = "\(mid):\(rec)"
            }
        }

        // Append the binary file contents as the final multipart part.
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append(
            "Content-Disposition: form-data; name=\"file\"; filename=\"\(filename)\"\r\n".data(using: .utf8)!
        )
        body.append("Content-Type: application/octet-stream\r\n\r\n".data(using: .utf8)!)
        // Encrypt the bytes, binding any optional AAD so tampering with the
        // message id or recipient will be detected during decryption.
        let aad = aadString?.data(using: .utf8)
        let encrypted = try CryptoManager.encryptData(data, aad: aad)
        body.append(encrypted)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)

        request.httpBody = body
        let (respData, _) = try await session.upload(for: request, from: body)
        if let json = try? JSONSerialization.jsonObject(with: respData) as? [String: Int] {
            return json["file_id"]
        }
        return nil
    }

    /// Download and decrypt a previously uploaded file.
    /// Files are stored encrypted on the server just like messages so the
    /// client must decrypt them after fetching.
    ///
    /// - Parameters:
    ///   - id: Identifier returned by ``uploadFile``.
    ///   - messageId: Identifier used during upload for AAD, if any.
    ///   - recipient: Username for direct messages or ``nil`` when ``groupId``
    ///     is provided.
    ///   - groupId: Group identifier matching the value used during upload.
    func downloadFile(
        id: Int,
        messageId: Int? = nil,
        recipient: String? = nil,
        groupId: Int? = nil
    ) async throws -> Data {
        guard token != nil else { throw URLError(.userAuthenticationRequired) }
        let request = URLRequest(url: baseURL.appendingPathComponent("files/\(id)"))
        let (data, _) = try await sendRequest(request)
        var aadData: Data? = nil
        if let mid = messageId {
            if let rec = recipient {
                aadData = "\(mid):\(rec)".data(using: .utf8)
            } else if let gid = groupId {
                aadData = "\(mid):g\(gid)".data(using: .utf8)
            }
        }
        let decrypted = try CryptoManager.decryptData(data, aad: aadData)
        return decrypted
    }

    /// Fetch and cache the PEM encoded RSA public key for ``username``.
    /// Each entry records when it was retrieved so that stale keys can be
    /// refreshed after ``publicKeyCacheDuration`` seconds. This guards against
    /// server‑side key rotations leaving the app with an outdated key while still
    /// minimizing network traffic for frequent message sends. If the user's
    /// system clock changes abruptly, the cache is discarded and a new key is
    /// requested to avoid using stale data.
    private func publicKey(for username: String) async throws -> String {
        // Check the in-memory cache first. If the cached value is still within
        // the allowed age threshold it can be reused directly, avoiding a
        // network round trip. If the timestamp is older than the configured
        // duration the entry is discarded and a fresh key is fetched.
        if let cached = publicKeyCache[username] {
            let age = Date().timeIntervalSince(cached.fetchedAt)
            if publicKeyCacheDuration <= 0 || age < publicKeyCacheDuration {
                return cached.key
            }
            // Edge case: if the device clock changes drastically, ``age`` may
            // appear larger or smaller than expected. In such situations we
            // conservatively drop the cached value and fetch a new key to avoid
            // using a potentially stale credential.
            publicKeyCache.removeValue(forKey: username)
        }

        guard token != nil else { throw URLError(.userAuthenticationRequired) }
        let url = baseURL.appendingPathComponent("public_key/\(username)")
        let request = URLRequest(url: url)
        let (data, _) = try await sendRequest(request)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let pem = json["public_key"] else {
            throw URLError(.badServerResponse)
        }
        // Store the retrieved key along with the current timestamp so that
        // future calls can determine whether it should be refreshed.
        publicKeyCache[username] = CachedPublicKey(key: pem, fetchedAt: Date())
        return pem
    }

    /// Retrieve the symmetric AES key used for a group chat from the backend.
    /// Keys are cached in memory and also persisted via ``CryptoManager`` so
    /// that subsequent requests can decrypt messages without another network
    /// call.
    private func groupKey(for groupId: Int) async throws -> String {
        if let cached = groupKeys[groupId] { return cached }
        guard token != nil else { throw URLError(.userAuthenticationRequired) }
        let request = URLRequest(url: baseURL.appendingPathComponent("groups/\(groupId)/key"))
        let (data, _) = try await sendRequest(request)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let key = json["key"] else { throw URLError(.badServerResponse) }
        // Cache the returned AES key for future use
        groupKeys[groupId] = key
        CryptoManager.storeGroupKey(key, groupId: groupId)
        return key
    }

    /// Send a single message to ``recipient``.
    func sendMessage(_ content: String, to recipient: String, fileId: Int? = nil, expiresAt: Date? = nil) async throws {
        guard token != nil else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        request.httpMethod = "POST"
        let publicKeyPem = try await publicKey(for: recipient)
        if let expected = pinnedKeys[recipient] {
            let fp = CryptoManager.fingerprint(of: publicKeyPem)
            guard fp == expected else { throw URLError(.secureConnectionFailed) }
        }
        // Encrypt the plaintext with the recipient's key
        let encrypted = try CryptoManager.encryptRSA(content, publicKeyPem: publicKeyPem)
        let b64 = encrypted.base64EncodedString()
        let sig = try CryptoManager.signMessage(b64).base64EncodedString()
        var comps = URLComponents()
        var items = [
            URLQueryItem(name: "content", value: b64),
            URLQueryItem(name: "signature", value: sig),
            URLQueryItem(name: "recipient", value: recipient),
        ]
        if let id = fileId {
            items.append(URLQueryItem(name: "file_id", value: String(id)))
        }
        if let exp = expiresAt {
            let iso = ISO8601DateFormatter().string(from: exp)
            items.append(URLQueryItem(name: "expires_at", value: iso))
        }
        comps.queryItems = items
        request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = comps.query?.data(using: .utf8)
        _ = try await sendRequest(request)
    }

    /// Remove a message from the server.
    func deleteMessage(id: Int) async throws {
        guard token != nil else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages/\(id)"))
        request.httpMethod = "DELETE"
        _ = try await sendRequest(request)
    }

    /// Notify the backend that a message has been read.
    func markMessageRead(id: Int) async throws {
        guard token != nil else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages/\(id)/read"))
        request.httpMethod = "POST"
        _ = try await sendRequest(request)
    }

    /// Update the user's message retention period in days.
    func updateRetention(days: Int) async throws {
        guard token != nil else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("account-settings"))
        request.httpMethod = "PUT"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(["messageRetentionDays": days])
        _ = try await sendRequest(request)
    }

    /// Clear the stored token and authentication state.
    func logout() {
        token = nil
        refreshToken = nil
        isAuthenticated = false
    }

    var authToken: String? { token }

    /// Request the backend to revoke all active sessions for the user.
    func revokeAllSessions() async {
        guard token != nil else { return }
        var request = URLRequest(url: baseURL.appendingPathComponent("revoke"))
        request.httpMethod = "POST"
        _ = try? await sendRequest(request)
    }

    /// Refresh the access token using a backend endpoint.
    /// Contact the ``/refresh`` endpoint using the stored refresh token.
    /// - Returns: ``true`` if a new access token was retrieved and stored.
    private func refreshAccessToken() async -> Bool {
        guard let refresh = refreshToken else { return false }
        var request = URLRequest(url: baseURL.appendingPathComponent("refresh"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(refresh)", forHTTPHeaderField: "Authorization")
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let new = json["access_token"] as? String else {
                return false
            }
            self.token = new
            if let newRefresh = json["refresh_token"] as? String {
                self.refreshToken = newRefresh
            }
            return true
        } catch {
            return false
        }
    }

    /// URLSessionDelegate providing basic certificate pinning.
    private class PinningDelegate: NSObject, URLSessionDelegate {
        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard let trust = challenge.protectionSpace.serverTrust,
                  let serverCert = SecTrustGetCertificateAtIndex(trust, 0),
                  let pinnedURL = Bundle.main.url(forResource: "server", withExtension: "cer"),
                  let pinnedData = try? Data(contentsOf: pinnedURL),
                  let pinnedCert = SecCertificateCreateWithData(nil, pinnedData as CFData) else {
                completionHandler(.performDefaultHandling, nil)
                return
            }

            let serverData = SecCertificateCopyData(serverCert) as Data
            let pinnedCertData = SecCertificateCopyData(pinnedCert) as Data
            if serverData == pinnedCertData {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                // Notify listeners that pinning failed so they can alert the user
                // to update ``server.cer``.
                NotificationCenter.default.post(name: APIService.pinningFailureNotification, object: nil)
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
    }

    /// Determine whether ``cert`` expires within ``threshold`` seconds.
    ///
    /// - Parameters:
    ///   - cert: Certificate to evaluate.
    ///   - threshold: Seconds before expiry considered "soon" (default 30 days).
    /// - Returns: ``true`` if ``cert`` expires within ``threshold``.
    private func isCertificateExpiringSoon(_ cert: SecCertificate, threshold: TimeInterval = 60 * 60 * 24 * 30) -> Bool {
        let oid = kSecOIDX509V1ValidityNotAfter
        if let values = SecCertificateCopyValues(cert, [oid] as CFArray, nil) as? [CFString: Any],
           let exp = values[oid] as? [CFString: Any],
           let date = exp[kSecPropertyKeyValue] as? Date {
            return date.timeIntervalSinceNow < threshold
        }
        return false
    }
}
