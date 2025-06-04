import Foundation

/// Wrapper around the Flask REST API used by the app.
/// It handles user authentication and message operations.
class APIService: ObservableObject {
    /// Base URL of the backend API, loaded from Info.plist.
    private let baseURL: URL

    /// Indicates whether the user is currently authenticated.
    @Published var isAuthenticated = false

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
        if let stored = KeychainService.loadToken() {
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
        let (data, _) = try await URLSession.shared.data(for: request)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = json["access_token"] as? String else {
            throw URLError(.badServerResponse)
        }
        DispatchQueue.main.async {
            self.token = token
            self.isAuthenticated = true
        }
    }

    /// Register a new user.
    func register(username: String, email: String, password: String) async throws {
        let url = baseURL.appendingPathComponent("register")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let body = ["username": username, "email": email, "password": password]
        request.httpBody = body.map { "\($0)=\($1)" }.joined(separator: "&").data(using: .utf8)
        let (_, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 201 else {
            throw URLError(.badServerResponse)
        }
    }

    /// Fetch all messages for the authenticated user.
    func fetchMessages() async throws -> [Message] {
        guard let token = token else { return [] }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await URLSession.shared.data(for: request)
        let json = try JSONDecoder().decode([String: [Message]].self, from: data)
        return json["messages"] ?? []
    }

    /// Send a single message to the server.
    func sendMessage(_ content: String) async throws -> Message {
        guard let token = token else { throw URLError(.userAuthenticationRequired) }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let encrypted = try CryptoManager.encryptMessage(content)
        request.httpBody = "content=\(String(decoding: encrypted, as: UTF8.self))".data(using: .utf8)
        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(Message.self, from: data)
    }

    func logout() {
        token = nil
        isAuthenticated = false
    }

    var authToken: String? { token }
}
