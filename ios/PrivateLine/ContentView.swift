/*
 * ContentView.swift - SwiftUI entry point for the iOS client.
 * Displays login or chat screens and now surfaces certificate pinning warnings
 * if the bundled SPKI fingerprints in ``server_fingerprints.txt`` do not match
 * the server. This guides users to refresh their app when the backend certificate
 * changes.
*/
import SwiftUI

/// Root view that displays either the login screen or chat depending on auth state.
struct ContentView: View {
    /// Shared API service used across the app.
    @StateObject private var api = APIService()
    /// Remembers whether the onboarding screen has been displayed.
    @AppStorage("hasSeenOnboarding") private var hasSeenOnboarding = false
    /// Persisted color scheme preference.
    @AppStorage("isDarkMode") private var isDarkMode = false

    var body: some View {
        NavigationStack {
            // Show onboarding once for new installs
            if !hasSeenOnboarding {
                OnboardingView()
            } else if api.isAuthenticated {
                // Main tab interface after login
                TabView {
                    ChatView(viewModel: ChatViewModel(api: api))
                        .tabItem {
                            Label("Chats", systemImage: "bubble.left.and.bubble.right.fill")
                        }
                    SettingsView(api: api)
                        .tabItem {
                            Label("Settings", systemImage: "gear")
                        }
                }
                .navigationTitle("PrivateLine")
            } else {
                // Prompt the user to log in or register
                LoginView(viewModel: LoginViewModel(api: api))
                    .navigationTitle("PrivateLine")
            }
        }
        // Respect the user's dark mode preference
        .preferredColorScheme(isDarkMode ? .dark : .light)
        // Warn the user when certificate pinning fails so they know to update.
        .alert(
            "Connection Untrusted",
            isPresented: $api.showCertificateWarning
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("The server's certificate doesn't match the one bundled with the app. Please update the app or contact support to refresh the pinned certificate.")
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
