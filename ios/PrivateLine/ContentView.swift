import SwiftUI

/// Main screen that displays either the login form or the chat view
/// depending on the authentication state.
struct ContentView: View {
    /// Service used to communicate with the backend.
    @StateObject private var api = APIService()
    /// Username entered on the login form.
    @State private var username = ""
    /// Password entered on the login form.
    @State private var password = ""
    /// Current message text in the chat box.
    @State private var message = ""
    /// List of messages fetched from the backend.
    @State private var messages: [Message] = []

    var body: some View {
        NavigationView {
            VStack {
                if api.isAuthenticated {
                    // Chat view shown after a successful login
                    List(messages) { msg in
                        Text(msg.content)
                    }
                    HStack {
                        TextField("Message", text: $message)
                        Button("Send") {
                            api.sendMessage(message) { fetched in
                                if let fetched = fetched {
                                    messages.append(fetched)
                                }
                            }
                            // Clear the input after sending
                            message = ""
                        }
                    }
                } else {
                    // Login form displayed when not authenticated
                    TextField("Username", text: $username)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    SecureField("Password", text: $password)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                    Button("Login") {
                        api.login(username: username, password: password) { success in
                            if success {
                                api.fetchMessages { fetched in
                                    messages = fetched
                                }
                            }
                        }
                    }
                }
            }
            .padding()
            .navigationTitle("PrivateLine")
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    /// Render a preview for Xcode's canvas
    static var previews: some View {
        ContentView()
    }
}
