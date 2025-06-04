import Foundation

/// Simple wrapper around the Flask REST API used by the app.
/// It handles user authentication and basic message operations.
class APIService: ObservableObject {
    /// Base URL of the backend API. Adjust this if the server runs elsewhere.
    private let baseURL = URL(string: "http://localhost:5000/api")!

    /// Indicates whether the user is currently authenticated.
    @Published var isAuthenticated = false

    /// JWT token returned after a successful login.
    private var token: String?

    /// Attempt to log in with the provided credentials.
    /// - Parameters:
    ///   - username: Account username
    ///   - password: Account password
    ///   - completion: Called with `true` on success
    func login(username: String, password: String, completion: @escaping (Bool) -> Void) {
        let url = baseURL.appendingPathComponent("login")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONEncoder().encode(["username": username, "password": password])

        URLSession.shared.dataTask(with: request) { data, response, _ in
            guard
                let data = data,
                let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let token = json["access_token"] as? String
            else {
                DispatchQueue.main.async { completion(false) }
                return
            }
            DispatchQueue.main.async {
                self.token = token
                self.isAuthenticated = true
                completion(true)
            }
        }.resume()
    }

    /// Fetch all messages for the authenticated user.
    func fetchMessages(completion: @escaping ([Message]) -> Void) {
        // Ensure we have a token before making the request
        guard let token = token else { return }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        URLSession.shared.dataTask(with: request) { data, _, _ in
            guard let data = data,
                  let json = try? JSONDecoder().decode([String: [Message]].self, from: data),
                  let messages = json["messages"]
            else {
                DispatchQueue.main.async { completion([]) }
                return
            }
            DispatchQueue.main.async { completion(messages) }
        }.resume()
    }

    /// Send a single message to the server.
    func sendMessage(_ content: String, completion: @escaping (Message?) -> Void) {
        guard let token = token else { return }
        var request = URLRequest(url: baseURL.appendingPathComponent("messages"))
        request.httpMethod = "POST"
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.httpBody = "content=\(content)".data(using: .utf8)
        URLSession.shared.dataTask(with: request) { data, _, _ in
            guard let data = data,
                  let message = try? JSONDecoder().decode(Message.self, from: data)
            else {
                DispatchQueue.main.async { completion(nil) }
                return
            }
            DispatchQueue.main.async { completion(message) }
        }.resume()
    }
}
