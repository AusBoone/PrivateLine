import Foundation
import LocalAuthentication

/// Wrapper around the Flask REST API used by the app.
/// It handles user authentication and message operations.
class APIService: ObservableObject {
    /// Base URL of the backend API, loaded from Info.plist.
    private let baseURL: URL
    var baseURLString: String { baseURL.absoluteString }

    /// Indicates whether the user is currently authenticated.
    @Published var isAuthenticated = false

    /// Count the number of failed login attempts.
    private var loginFailures = 0

    /// Cache of fetched recipient public keys
    private var publicKeyCache: [String: String] = [:]

    /// Stored pinned fingerprints
    private var pinnedKeys: [String: String] = [:]
    @Published var groups: [Group] = []
    private var groupKeys: [Int: String] = [:]

    /// URLSession used for API calls with certificate pinning.
    private let session: URLSession

    /// JWT token returned after a successful login.
    private var token: String? {
        didSet {
            if let token = token {
                KeychainService.saveToken(token)
            } else {
                KeychainService.removeToken()
            }
        }
    }

    init() {
        if let urlString = Bundle.main.object(forInfoDictionaryKey: "BackendBaseURL") as? String,
           let url = URL(string: urlString) {
            baseURL = url
        } else {
            baseURL = URL(string: "http://localhost:5000/api")!
        }

        // Configure pinned session
        let config = URLSessionConfiguration.default
        session = URLSession(configuration: config, delegate: PinningDelegate(), delegateQueue: nil)

        // Attempt to load the stored token, prompting for Face ID/Touch ID.
        let context = LAContext()
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
            let reason = "Authenticate to unlock PrivateLine"
            if (try? context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)) == true,
               let stored = KeychainService.loadToken(context: context) {
                token = stored
                isAuthenticated = true
            }
        } else if let stored = KeychainService.loadToken() {
            // Fallback if biometrics unavailable
            token = stored
            isAuthenticated = true
        }
    }

    /// Attempt to log in with the provided credentials.
    func login(username: String, password: String) async throws {
        let url = baseURL.appendingPathComponent("login")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(["username": username, "password": password])
        do {
            let (data, _) = try await session.data(for: request)
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let token = json["access_token"] as? String else {
                throw URLError(.badServerResponse)
            }
           loginFailures = 0
           try? CryptoManager.loadPrivateKey(password: password)
            self.token = token
            do {
                var request = URLRequest(url: self.baseURL.appendingPathComponent("pinned_keys"))
                request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                let (pkData, _) = try await self.session.data(for: request)
                if let json = try? JSONSerialization.jsonObject(with: pkData) as? [String: [[String: String]]],
                   let arr = json["pinned_keys"] {
                    self.pinnedKeys = Dictionary(uniqueKeysWithValues: arr.map { ($0["username"]!, $0["fingerprint"]!) })
                }
            } catch {
                self.pinnedKeys = [:]
            }
            DispatchQueue.main.async {
                self.isAuthenticated = true
            }
        } catch {
            loginFailures += 1
            if loginFailures >= 3 {
                KeychainService.removeToken()
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
        let body = ["username": username, "email": email, "password": password]
        request.httpBody = body.map { "\($0)=\($1)" }.joined(separator: "&").data(using: .utf8)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 201 else {
            throw URLError(.badServerResponse)
        }
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
           let enc = json["encrypted_private_key"],
           let salt = json["salt"],
           let nonce = json["nonce"] {
            let fp = json["fingerprint"]
            CryptoManager.storeKeyMaterial(.init(encrypted_private_key: enc, salt: salt, nonce: nonce, fingerprint: fp))
            if let fp = fp {
                print("Fingerprint: \(fp)")
            }
        }
    }

    /// Fetch all messages for the authenticated user.
    func fetchMessages() async throws -> [Message] {
        guard let token = token else { return [] }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await session.data(for: request)
        let json = try JSONDecoder().decode([String: [Message]].self, from: data)
        let msgs = json["messages"] ?? []
        return msgs.compactMap { msg in
            if let text = try? CryptoManager.decryptRSA(msg.content) {
                return Message(id: msg.id, content: text, file_id: msg.file_id, read: msg.read)
            }
            return nil
        }
    }

    /// Retrieve and decrypt all messages for the given group.
    func fetchGroupMessages(_ id: Int) async throws -> [Message] {
        guard let token = token else { return [] }
        _ = try await groupKey(for: id)
        var request = URLRequest(url: baseURL.appendingPathComponent("groups/\(id)/messages"))
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await session.data(for: request)
        let json = try JSONDecoder().decode([String: [Message]].self, from: data)
        let msgs = json["messages"] ?? []
        return msgs.compactMap { msg in
            guard let data = Data(base64Encoded: msg.content) else { return nil }
            if let text = try? CryptoManager.decryptGroupMessage(data, groupId: id) {
                return Message(id: msg.id, content: text, file_id: msg.file_id, read: msg.read)
            }
            return nil
        }
    }

    /// Fetch the list of available chat groups from the backend.
    func fetchGroups() async throws -> [Group] {
        guard let token = token else { return [] }
        var request = URLRequest(url: baseURL.appendingPathComponent("groups"))
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await session.data(for: request)
        let json = try JSONDecoder().decode([String: [Group]].self, from: data)
        let gs = json["groups"] ?? []
        DispatchQueue.main.async { self.groups = gs }
        return gs
    }

    /// Encrypt ``content`` with the group key and POST it to the server.
    func sendGroupMessage(_ content: String, groupId: Int, fileId: Int? = nil) async throws {
        guard let token = token else { throw URLError(.userAuthenticationRequired) }
        _ = try await groupKey(for: groupId)
        var request = URLRequest(url: baseURL.appendingPathComponent("groups/\(groupId)/messages"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let encrypted = try CryptoManager.encryptGroupMessage(content, groupId: groupId)
        let b64 = encrypted.base64EncodedString()
        let sig = try CryptoManager.signMessage(b64).base64EncodedString()
        var body = "content=\(b64)&group_id=\(groupId)&signature=\(sig)"
        if let id = fileId {
            body.append("&file_id=\(id)")
        }
        request.httpBody = body.data(using: .utf8)
        _ = try await session.data(for: request)
    }

    /// Encrypt ``data`` and upload it as ``filename``.
    func uploadFile(data: Data, filename: String) async throws -> Int? {
        guard let token = token else { return nil }
        var request = URLRequest(url: baseURL.appendingPathComponent("files"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let boundary = UUID().uuidString
        request.addValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"\(filename)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/octet-stream\r\n\r\n".data(using: .utf8)!)
        let encrypted = try CryptoManager.encryptData(data)
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
    func downloadFile(id: Int) async throws -> Data {
        guard let token = token else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("files/\(id)"))
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await session.data(for: request)
        let decrypted = try CryptoManager.decryptData(data)
        return decrypted
    }

    /// Fetch and cache the public key for ``username``.
    private func publicKey(for username: String) async throws -> String {
        if let cached = publicKeyCache[username] {
            return cached
        }
        guard let token = token else { throw URLError(.userAuthenticationRequired) }
        let url = baseURL.appendingPathComponent("public_key/\(username)")
        var request = URLRequest(url: url)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await session.data(for: request)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let pem = json["public_key"] else {
            throw URLError(.badServerResponse)
        }
        publicKeyCache[username] = pem
        return pem
    }

    /// Fetch and cache the AES key for ``groupId``.
    private func groupKey(for groupId: Int) async throws -> String {
        if let cached = groupKeys[groupId] { return cached }
        guard let token = token else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("groups/\(groupId)/key"))
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await session.data(for: request)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: String],
              let key = json["key"] else { throw URLError(.badServerResponse) }
        groupKeys[groupId] = key
        CryptoManager.storeGroupKey(key, groupId: groupId)
        return key
    }

    /// Send a single message to ``recipient``.
    func sendMessage(_ content: String, to recipient: String, fileId: Int? = nil) async throws {
        guard let token = token else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let publicKeyPem = try await publicKey(for: recipient)
        if let expected = pinnedKeys[recipient] {
            let fp = CryptoManager.fingerprint(of: publicKeyPem)
            guard fp == expected else { throw URLError(.secureConnectionFailed) }
        }
        let encrypted = try CryptoManager.encryptRSA(content, publicKeyPem: publicKeyPem)
        let b64 = encrypted.base64EncodedString()
        let sig = try CryptoManager.signMessage(b64).base64EncodedString()
        var body = "content=\(b64)&signature=\(sig)&recipient=\(recipient)"
        if let id = fileId {
            body.append("&file_id=\(id)")
        }
        request.httpBody = body.data(using: .utf8)
        _ = try await session.data(for: request)
    }

    /// Remove a message from the server.
    func deleteMessage(id: Int) async throws {
        guard let token = token else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages/\(id)"))
        request.httpMethod = "DELETE"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        _ = try await session.data(for: request)
    }

    /// Notify the backend that a message has been read.
    func markMessageRead(id: Int) async throws {
        guard let token = token else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages/\(id)/read"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        _ = try await session.data(for: request)
    }

    /// Clear the stored token and authentication state.
    func logout() {
        token = nil
        isAuthenticated = false
    }

    var authToken: String? { token }

    /// Request the backend to revoke all active sessions for the user.
    func revokeAllSessions() async {
        guard let token = token else { return }
        var request = URLRequest(url: baseURL.appendingPathComponent("revoke"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        _ = try? await session.data(for: request)
    }

    /// Refresh the access token using a backend endpoint.
    func refreshToken() async {
        guard let token = token else { return }
        var request = URLRequest(url: baseURL.appendingPathComponent("refresh"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        if let (data, _) = try? await session.data(for: request),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let new = json["access_token"] as? String {
            self.token = new
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
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
    }
}
