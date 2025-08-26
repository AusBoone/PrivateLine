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
 *
 * 2025 networking hardening: device token registration now performs TLS
 * certificate pinning using ``APIService.PinningDelegate`` and reports
 * failures via ``registrationFailureNotification`` so the UI may retry.
*/

/// Helper used for configuring push notification permissions and
/// registering the device token with the backend. The token is cached in
/// ``UserDefaults`` so changes can be detected and re-submitted to the server.
enum NotificationManager {
    /// Storage key used for persisting the last known APNs token. Using a
    /// constant avoids typos and centralises the value for future updates.
    private static let tokenKey = "apnsDeviceToken"

    /// Notification emitted when the push token registration fails. The UI can
    /// observe this to prompt the user to retry the operation.
    static let registrationFailureNotification = Notification.Name("DeviceTokenRegistrationFailed")

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
    static func registerDeviceToken(
        _ deviceToken: Data,
        session: URLSession? = nil,
        baseURL: URL? = nil,
        authToken: String? = nil
    ) {
        // Convert binary token to a hex string representation so it can be
        // transmitted as JSON. APNs tokens are opaque, hence the hex encoding.
        let tokenString = deviceToken.map { String(format: "%02x", $0) }.joined()

        // Detect whether this token matches the last value we sent to the
        // server. APNs may resend the same token on each launch; avoiding a
        // network request in that case conserves battery and bandwidth.
        let defaults = UserDefaults.standard
        if defaults.string(forKey: tokenKey) == tokenString {
            return
        }

        // Retrieve the auth token. Tests may inject a pre-defined value to
        // bypass Keychain access which requires iOS APIs.
        let context = LAContext()
        guard let auth = authToken ?? (try? KeychainService.loadToken(context: context)) else { return }

        // Determine the backend endpoint. Tests may supply ``baseURL`` to avoid
        // relying on Info.plist configuration.
        let base: URL
        if let provided = baseURL {
            base = provided
        } else if let urlString = Bundle.main.object(forInfoDictionaryKey: "BackendBaseURL") as? String,
                  let url = URL(string: urlString) {
            base = url
        } else {
            return
        }
        let url = base.appendingPathComponent("push-token")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("Bearer \(auth)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["token": tokenString, "platform": "ios"]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        // Use the supplied session or create one with certificate pinning so the
        // token is only sent to trusted servers.
        let session = session ?? URLSession(
            configuration: .default,
            delegate: APIService.PinningDelegate(),
            delegateQueue: nil
        )

        session.dataTask(with: request) { _, response, error in
            // Any network or server error should prevent caching the token so a
            // subsequent attempt can retry the request. Post a notification so
            // the UI may inform the user.
            guard error == nil,
                  let http = response as? HTTPURLResponse,
                  (200..<300).contains(http.statusCode) else {
                defaults.removeObject(forKey: tokenKey)
                NotificationCenter.default.post(name: registrationFailureNotification, object: error)
                return
            }

            // Persist the token only after the server acknowledges receipt.
            defaults.set(tokenString, forKey: tokenKey)
        }.resume()
    }
}
