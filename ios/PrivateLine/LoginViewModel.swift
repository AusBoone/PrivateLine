import Foundation
import Combine

@MainActor
final class LoginViewModel: ObservableObject {
    @Published var username = ""
    @Published var password = ""
    @Published var email = ""
    @Published var isRegistering = false
    @Published var errorMessage: String?

    private let api: APIService

    init(api: APIService) {
        self.api = api
    }

    func login() async {
        guard !username.isEmpty, password.count >= 4 else {
            errorMessage = "Please enter a username and password"
            return
        }
        do {
            try await api.login(username: username, password: password)
        } catch {
            errorMessage = "Login failed: \(error.localizedDescription)"
        }
    }

    func register() async {
        guard email.contains("@"), password.count >= 8 else {
            errorMessage = "Enter a valid email and a strong password"
            return
        }
        do {
            try await api.register(username: username, email: email, password: password)
            isRegistering = false
        } catch {
            errorMessage = "Registration failed: \(error.localizedDescription)"
        }
    }
}
