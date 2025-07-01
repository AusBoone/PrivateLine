/*
 * SettingsView.swift - User preferences and account actions.
 * Provides logout, session revocation and push toggle.
 */
import SwiftUI
import UIKit

/// Simple settings screen allowing logout and session revocation.
struct SettingsView: View {
    /// API service instance for performing logout and revocation calls.
    @ObservedObject var api: APIService
    /// Persisted user preference controlling the color scheme.
    @AppStorage("isDarkMode") private var isDarkMode = false
    /// Whether push notifications are enabled. Changing this triggers
    /// registration or deregistration with APNs.
    @AppStorage("pushEnabled") private var pushEnabled = true

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
            Section(header: Text("Notifications")) {
                Toggle("Push Notifications", isOn: $pushEnabled)
                    .onChange(of: pushEnabled) { value in
                        if value {
                            NotificationManager.requestAuthorization()
                        } else {
                            UIApplication.shared.unregisterForRemoteNotifications()
                        }
                    }
            }
        }
        .navigationTitle("Settings")
    }
}

