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
    NotificationManager.requestAuthorization()
}

/// Application entry point.
@main
struct PrivateLineApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var delegate
    init() {
        configureNotifications()
    }
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
