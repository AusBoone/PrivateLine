import Foundation
import UserNotifications
import UIKit

/// Helper used for configuring push notification permissions and
/// registering the device token with the backend.
enum NotificationManager {
    /// Request notification authorization and register with APNs.
    static func requestAuthorization() {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            // Only register with APNs if the user granted permission
            guard granted else { return }
            DispatchQueue.main.async {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }

    /// Send the APNs device token to the backend so push notifications can be delivered.
    ///
    /// - Parameter deviceToken: Binary token provided by APNs during registration.
    static func registerDeviceToken(_ deviceToken: Data) {
        // Convert binary token to hex string
        let tokenString = deviceToken.map { String(format: "%02x", $0) }.joined()
        guard let auth = KeychainService.loadToken() else { return }
        guard let urlString = Bundle.main.object(forInfoDictionaryKey: "BackendBaseURL") as? String,
              let url = URL(string: urlString)?.appendingPathComponent("push-token") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("Bearer \(auth)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["token": tokenString, "platform": "ios"]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        // Fire and forget the registration request
        URLSession.shared.dataTask(with: request).resume()
    }
}
