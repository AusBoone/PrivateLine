import SwiftUI

/// Simple settings screen allowing logout and session revocation.
struct SettingsView: View {
    /// API service instance for performing logout and revocation calls.
    @ObservedObject var api: APIService
    /// Persisted user preference controlling the color scheme.
    @AppStorage("isDarkMode") private var isDarkMode = false

    var body: some View {
        Form {
            Section(header: Text("Account")) {
                // Clear the stored token and return to login
                Button("Logout") { api.logout() }
                // Invalidate other active sessions on the server
                Button("Revoke Sessions") { Task { await api.revokeAllSessions() } }
            }
            Section(header: Text("Appearance")) {
                // Persist user preference for dark mode
                Toggle("Dark Mode", isOn: $isDarkMode)
            }
        }
        .navigationTitle("Settings")
    }
}

