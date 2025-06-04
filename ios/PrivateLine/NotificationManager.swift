import Foundation
import UserNotifications
import UIKit

/// Helper used for configuring push notification permissions.
/// Currently the app only registers with APNs so that a device
/// token can be exchanged with the backend in the future.  No
/// server calls are performed here.
enum NotificationManager {
    /// Request notification authorization and register with APNs.
    static func requestAuthorization() {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            guard granted else { return }
            DispatchQueue.main.async {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }
}
