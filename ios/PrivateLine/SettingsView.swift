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
                Button("Logout") { api.logout() }
                Button("Revoke Sessions") { Task { await api.revokeAllSessions() } }
            }
            Section(header: Text("Appearance")) {
                Toggle("Dark Mode", isOn: $isDarkMode)
            }
        }
        .navigationTitle("Settings")
    }
}

