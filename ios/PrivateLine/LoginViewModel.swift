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
        do {
            try await api.login(username: username, password: password)
        } catch {
            errorMessage = "Login failed"
        }
    }

    func register() async {
        do {
            try await api.register(username: username, email: email, password: password)
            isRegistering = false
        } catch {
            errorMessage = "Registration failed"
        }
    }
}
