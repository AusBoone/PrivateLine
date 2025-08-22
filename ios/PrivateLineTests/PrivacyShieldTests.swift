// Unit tests exercising the session lock managed by ``PrivacyShield``.
//
// These tests validate that the UI overlay remains until the user successfully
// authenticates with biometrics or passcode. ``LAContext`` is mocked to simulate
// both success and failure without invoking actual device security mechanisms.
//
// Design decisions:
// - The tests post lifecycle notifications directly to mimic the app moving to
//   the background and back to the foreground.
// - ``MockContext`` subclasses ``LAContext`` so `PrivacyShield` can be tested in
//   isolation without hitting system APIs.

import XCTest
import LocalAuthentication
import UIKit
@testable import PrivateLine

/// Mock ``LAContext`` allowing tests to dictate authentication outcomes.
final class MockContext: LAContext {
    /// Controls the value returned by ``canEvaluatePolicy``.
    var canEvaluate: Bool = true
    /// Determines whether ``evaluatePolicy`` invokes its reply block with success.
    var evaluateSucceeds: Bool = true

    override func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        return canEvaluate
    }

    override func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping (Bool, Error?) -> Void) {
        // Call the reply handler synchronously for deterministic tests.
        reply(evaluateSucceeds, nil)
    }
}

/// Verifies that successful authentication clears the privacy overlay and resets
/// the failure flag.
final class PrivacyShieldTests: XCTestCase {
    /// Helper to allow asynchronous callbacks to complete.
    private func waitForAuthentication() {
        // Run the main loop briefly so DispatchQueue callbacks execute.
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.1))
    }

    /// Authentication success should reveal the UI and keep ``authFailed`` false.
    func testAuthenticationSuccessClearsOverlay() {
        let context = MockContext()
        context.evaluateSucceeds = true
        let shield = PrivacyShield(contextProvider: { context })

        // Simulate app moving to background.
        NotificationCenter.default.post(name: UIApplication.willResignActiveNotification, object: nil)
        XCTAssertTrue(shield.obscured)

        // Returning to foreground triggers authentication.
        NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
        waitForAuthentication()

        // Overlay should disappear and no error should be flagged.
        XCTAssertFalse(shield.obscured)
        XCTAssertFalse(shield.authFailed)
    }

    /// Failed authentication should keep the overlay visible and flag an error.
    func testAuthenticationFailureKeepsOverlay() {
        let context = MockContext()
        context.evaluateSucceeds = false
        let shield = PrivacyShield(contextProvider: { context })

        NotificationCenter.default.post(name: UIApplication.willResignActiveNotification, object: nil)
        XCTAssertTrue(shield.obscured)

        NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
        waitForAuthentication()

        XCTAssertTrue(shield.obscured)
        XCTAssertTrue(shield.authFailed)
    }
}
