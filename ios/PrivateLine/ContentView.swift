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
            if !hasSeenOnboarding {
                OnboardingView()
            } else if api.isAuthenticated {
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
                LoginView(viewModel: LoginViewModel(api: api))
                    .navigationTitle("PrivateLine")
            }
        }
        .preferredColorScheme(isDarkMode ? .dark : .light)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
