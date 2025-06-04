import SwiftUI

/// Configure push notifications when the app launches.
/// In a production application the device token would be sent
/// to the backend so that APNs can deliver new message alerts.
private func configureNotifications() {
    NotificationManager.requestAuthorization()
}

/// Application entry point.
@main
struct PrivateLineApp: App {
    init() {
        configureNotifications()
    }
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
