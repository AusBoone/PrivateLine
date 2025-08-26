import XCTest
@testable import PrivateLine

/// Tests covering the push-notification registration helper.
///
/// Focuses on error propagation so the UI can prompt users to retry when the
/// backend rejects the certificate presented during TLS handshake.
final class NotificationManagerTests: XCTestCase {
    /// Simulates a connection to a server whose certificate is not pinned.
    /// A delegate cancels the authentication challenge, mirroring how
    /// ``APIService.PinningDelegate`` reacts to unknown fingerprints. The test
    /// verifies that ``NotificationManager`` posts a failure notification and
    /// avoids caching the token so a subsequent attempt can retry.
    func testRegistrationFailsForUnpinnedCertificate() {
        // Ensure a clean slate so persistence checks are accurate.
        UserDefaults.standard.removeObject(forKey: "apnsDeviceToken")

        // Expect a failure notification which indicates that the registration
        // did not succeed and the UI should offer a retry option.
        let exp = expectation(forNotification: NotificationManager.registrationFailureNotification,
                              object: nil,
                              handler: nil)

        // Sample token content; the actual value is irrelevant for the test.
        let token = Data([0x00, 0x01, 0x02, 0x03])

        // Delegate that rejects all TLS challenges to mimic an unpinned cert.
        class RejectingDelegate: NSObject, URLSessionDelegate {
            func urlSession(_ session: URLSession,
                            didReceive challenge: URLAuthenticationChallenge,
                            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        }
        let session = URLSession(configuration: .default,
                                 delegate: RejectingDelegate(),
                                 delegateQueue: nil)

        // Attempt to register against an arbitrary HTTPS endpoint. The request
        // will fail during the TLS handshake due to the rejecting delegate.
        NotificationManager.registerDeviceToken(token,
                                                session: session,
                                                baseURL: URL(string: "https://example.com")!,
                                                authToken: "dummy")

        wait(for: [exp], timeout: 5.0)

        // After failure the token should remain unset to allow a retry.
        XCTAssertNil(UserDefaults.standard.string(forKey: "apnsDeviceToken"),
                     "Token should not persist after failed registration")
    }
}
