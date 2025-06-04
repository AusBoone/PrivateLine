import Foundation
import LocalAuthentication

/// Wrapper around the Flask REST API used by the app.
/// It handles user authentication and message operations.
class APIService: ObservableObject {
    /// Base URL of the backend API, loaded from Info.plist.
    private let baseURL: URL

    /// Indicates whether the user is currently authenticated.
    @Published var isAuthenticated = false

    /// Count the number of failed login attempts.
    private var loginFailures = 0

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
            DispatchQueue.main.async {
                self.token = token
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
        let body = ["username": username, "email": email, "password": password]
        request.httpBody = body.map { "\($0)=\($1)" }.joined(separator: "&").data(using: .utf8)
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 201 else {
            throw URLError(.badServerResponse)
        }
    }

    /// Fetch all messages for the authenticated user.
    func fetchMessages() async throws -> [Message] {
        guard let token = token else { return [] }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await session.data(for: request)
        let json = try JSONDecoder().decode([String: [Message]].self, from: data)
        return json["messages"] ?? []
    }

    /// Send a single message to the server.
    func sendMessage(_ content: String) async throws -> Message {
        guard let token = token else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        // Encrypt locally and send Base64 ciphertext to the backend
        let encrypted = try CryptoManager.encryptMessage(content)
        let b64 = encrypted.base64EncodedString()
        request.httpBody = "content=\(b64)".data(using: .utf8)
        let (data, _) = try await session.data(for: request)
        return try JSONDecoder().decode(Message.self, from: data)
    }

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

            if serverCert == pinnedCert {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
    }
}
