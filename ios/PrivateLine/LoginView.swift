import SwiftUI

struct LoginView: View {
    @StateObject var viewModel: LoginViewModel

    var body: some View {
        VStack {
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
                Button("Login") { Task { await viewModel.login() } }
                Button("Create Account") { viewModel.isRegistering = true }
            }
            if let error = viewModel.errorMessage {
                Text(error).foregroundColor(.red)
            }
        }
        .padding()
    }
}
