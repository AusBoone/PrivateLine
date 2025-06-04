import SwiftUI

struct LoginView: View {
    @StateObject var viewModel: LoginViewModel

    var body: some View {
        VStack(spacing: 12) {
            if viewModel.isRegistering {
                TextField("Username", text: $viewModel.username)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                TextField("Email", text: $viewModel.email)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                SecureField("Password", text: $viewModel.password)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                Button("Register") {
                    Task { await viewModel.register() }
                }
                Button("Back to Login") { viewModel.isRegistering = false }
            } else {
                TextField("Username", text: $viewModel.username)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                SecureField("Password", text: $viewModel.password)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                Button(action: { Task { await viewModel.login() } }) {
                    Label("Login", systemImage: "lock.open")
                }
                Button("Create Account") { viewModel.isRegistering = true }
            }
            if let error = viewModel.errorMessage {
                Text(error).foregroundColor(.red)
                    .accessibilityLabel("Error: \(error)")
            }
        }
        .padding()
    }
}
