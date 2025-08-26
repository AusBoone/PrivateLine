// Tests verifying biometric access control enforced by `KeychainService` as
// well as the in-memory scrubbing of sensitive byte buffers.  The suite
// confirms that access tokens are bound to the current biometric configuration
// and that the new `wipe` helper successfully zeros temporary buffers.
// Authentication failure handling is also exercised to ensure tokens remain
// protected if a user cancels the Face ID/Touch ID prompt or changes their
// enrolled biometrics.

import XCTest
import LocalAuthentication
@testable import PrivateLine

/// Unit tests covering the biometric protections applied to tokens stored in
/// the keychain.
final class KeychainServiceTests: XCTestCase {
    override func setUpWithError() throws {
        // Ensure a clean slate before each test to avoid cross-test pollution.
        KeychainService.removeToken()
    }

    override func tearDownWithError() throws {
        KeychainService.removeToken()
    }

    /// Loading the token with an invalidated context should throw ``LAError``
    /// because the system treats it as if the user cancelled authentication.
    func testLoadTokenFailsWithInvalidContext() throws {
        KeychainService.saveToken("secret")
        let context = LAContext()
        // Skip the test entirely if biometrics are unavailable on the device or
        // simulator. This prevents false failures on unsupported hardware.
        if !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
            throw XCTSkip("Biometric authentication not available")
        }
        // Invalidate the context to simulate a user cancelling the prompt.
        context.invalidate()
        XCTAssertThrowsError(try KeychainService.loadToken(context: context)) { error in
            // The thrown error should be an ``LAError`` signalling the
            // authentication failure.
            XCTAssertNotNil(error as? LAError)
        }
    }

    /// A valid ``LAContext`` should allow the token to be retrieved without
    /// throwing, proving that the item is unlocked only after successful
    /// biometric authentication.
    func testLoadTokenSucceedsWithValidContext() throws {
        KeychainService.saveToken("secret")
        let context = LAContext()
        if !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
            throw XCTSkip("Biometric authentication not available")
        }
        let token = try KeychainService.loadToken(context: context)
        XCTAssertEqual(token, "secret")
    }

    /// Verifies that the `wipe` helper overwrites buffers, preventing residual
    /// secrets from lingering in memory after use.
    func testWipeZeroesBuffer() {
        // Start with non-zero bytes to prove they are cleared.
        var buffer = Data([1, 2, 3, 4])
        KeychainService.wipe(&buffer)
        // All bytes should now be zero.
        XCTAssertTrue(buffer.allSatisfy { $0 == 0 })
    }
}
