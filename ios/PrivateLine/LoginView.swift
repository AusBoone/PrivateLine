import SwiftUI

/// View presenting login and registration forms.
struct LoginView: View {
    /// Source of truth for authentication fields and actions.
    @StateObject var viewModel: LoginViewModel

    var body: some View {
        VStack(spacing: 12) {
            // Toggle between registration and login forms.
            if viewModel.isRegistering {
                TextField("Username", text: $viewModel.username)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                TextField("Email", text: $viewModel.email)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                SecureField("Password", text: $viewModel.password)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                // Submit registration details to the backend
                Button("Register") {
                    Task { await viewModel.register() }
                }
                Button("Back to Login") { viewModel.isRegistering = false }
            } else {
                TextField("Username", text: $viewModel.username)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                SecureField("Password", text: $viewModel.password)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                // Trigger an async login request
                Button(action: { Task { await viewModel.login() } }) {
                    Label("Login", systemImage: "lock.open")
                }
                // Switch to the registration form
                Button("Create Account") { viewModel.isRegistering = true }
            }
            // Display backend error messages inline.
            if let error = viewModel.errorMessage {
                // Show any login or registration failures
                Text(error).foregroundColor(.red)
                    .accessibilityLabel("Error: \(error)")
            }
        }
        .padding()
    }
}
