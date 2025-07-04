import SwiftUI
import UIKit

class AppDelegate: NSObject, UIApplicationDelegate {
    /// Forward the APNs token to ``NotificationManager`` when registration succeeds.
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        NotificationManager.registerDeviceToken(deviceToken)
    }
}

/// Configure push notifications when the app launches.
/// In a production application the device token would be sent
/// to the backend so that APNs can deliver new message alerts.
private func configureNotifications() {
    // Ask the user for permission to send push notifications
    NotificationManager.requestAuthorization()
}

/// Application entry point.
@main
struct PrivateLineApp: App {
    /// Bridge UIKit delegate methods for push notifications.
    @UIApplicationDelegateAdaptor(AppDelegate.self) var delegate
    /// Controls whether a privacy overlay should obscure the UI.
    @StateObject private var shield = PrivacyShield()
    /// Perform one-time configuration when the app starts.
    init() {
        // Configure push notifications right away
        configureNotifications()
    }
    var body: some Scene {
        WindowGroup {
            ContentView()
                .privacyOverlay(shield: shield)
        }
    }
}
