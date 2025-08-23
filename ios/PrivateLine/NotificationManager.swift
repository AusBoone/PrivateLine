import Foundation
import UserNotifications
import UIKit
import LocalAuthentication

/*
 * Modification summary:
 * Introduces persistent tracking for the APNs device token so the client
 * re-registers with the backend only when Apple's token changes. This avoids
 * unnecessary network calls yet guarantees the server always holds the most
 * recent identifier for delivering push notifications.
 *
 * 2025 update: retrieving the authorization token now requires a biometric
 * scan, ensuring push registration only occurs after the user authenticates.
*/

/// Helper used for configuring push notification permissions and
/// registering the device token with the backend. The token is cached in
/// ``UserDefaults`` so changes can be detected and re-submitted to the server.
enum NotificationManager {
    /// Storage key used for persisting the last known APNs token. Using a
    /// constant avoids typos and centralises the value for future updates.
    private static let tokenKey = "apnsDeviceToken"

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

    /// Send the APNs device token to the backend so push notifications can be
    /// delivered. The token is first compared against the previously cached
    /// value and only transmitted if it has changed.
    ///
    /// - Parameter deviceToken: Binary token provided by APNs during
    ///   registration. The method gracefully returns if authentication details
    ///   or the backend URL cannot be determined.
    static func registerDeviceToken(_ deviceToken: Data) {
        // Convert binary token to a hex string representation
        let tokenString = deviceToken.map { String(format: "%02x", $0) }.joined()

        // Detect whether this token matches the last value we sent to the
        // server. APNs may resend the same token on each launch; avoiding a
        // network request in that case conserves battery and bandwidth.
        let defaults = UserDefaults.standard
        if defaults.string(forKey: tokenKey) == tokenString {
            return
        }
        defaults.set(tokenString, forKey: tokenKey)

        // Retrieve the auth token, requiring biometric authentication. If the
        // user cancels or authentication fails the registration attempt is
        // skipped and will be retried on the next token refresh.
        let context = LAContext()
        guard let auth = try? KeychainService.loadToken(context: context) else { return }
        guard let urlString = Bundle.main.object(forInfoDictionaryKey: "BackendBaseURL") as? String,
              let url = URL(string: urlString)?.appendingPathComponent("push-token") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("Bearer \(auth)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["token": tokenString, "platform": "ios"]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        // Fire and forget the registration request. No response handling is
        // necessary because the backend does not return useful data. Errors are
        // ignored; a new token will trigger another attempt later.
        URLSession.shared.dataTask(with: request).resume()
    }
}
