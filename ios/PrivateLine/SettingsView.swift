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
    /// Locally cached retention setting in days. ``AppStorage`` persists the
    /// value across launches so the message cache can consult the same TTL.
    @AppStorage("retention_days") private var retention = 30

    var body: some View {
        Form {
            Section(header: Text("Account")) {
                // Clear the stored token and return to login
                Button("Logout") { api.logout() }
                // Invalidate other active sessions on the server
                Button("Revoke Sessions") { Task { await api.revokeAllSessions() } }
                Stepper(value: $retention, in: 1...365, step: 1) {
                    Text("Retention: \(retention) days")
                }
                .onChange(of: retention) { newValue in
                    Task { try? await api.updateRetention(days: newValue) }
                }
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

