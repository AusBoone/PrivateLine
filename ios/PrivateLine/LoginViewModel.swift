import Foundation
import Combine

@MainActor
/// View model backing ``LoginView``. Performs authentication requests
/// and updates the UI via published properties.
final class LoginViewModel: ObservableObject {
    /// Username typed by the user.
    @Published var username = ""
    /// Password typed by the user.
    @Published var password = ""
    /// Email address used during registration.
    @Published var email = ""
    /// Whether the registration form is shown instead of the login form.
    @Published var isRegistering = false
    /// Optional error string displayed below the form.
    @Published var errorMessage: String?

    /// Underlying API service used to talk to the backend.
    private let api: APIService

    init(api: APIService) {
        self.api = api
    }

    /// Attempt to log in using the current ``username`` and ``password``.
    func login() async {
        guard !username.isEmpty, password.count >= 4 else {
            errorMessage = "Please enter a username and password"
            return
        }
        do {
            // Forward credentials to the API service
            try await api.login(username: username, password: password)
        } catch {
            errorMessage = "Login failed: \(error.localizedDescription)"
        }
    }

    /// Create a new account using the provided ``email`` and ``password``.
    func register() async {
        guard email.contains("@"), password.count >= 8 else {
            errorMessage = "Enter a valid email and a strong password"
            return
        }
        do {
            // Send the registration request to the backend
            try await api.register(username: username, email: email, password: password)
            isRegistering = false
        } catch {
            errorMessage = "Registration failed: \(error.localizedDescription)"
        }
    }
}
