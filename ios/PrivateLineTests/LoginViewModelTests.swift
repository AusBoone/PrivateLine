/*
 * LoginViewModelTests.swift - Unit tests for LoginViewModel.
 * Verifies loading state toggling and validation error handling for
 * authentication actions.
 */
import XCTest
@testable import PrivateLine

/// Mock API service for authentication endpoints with controllable delays and
/// failure switches. This allows deterministic tests without real networking.
final class AuthMockAPI: APIService {
    enum Failure: Error { case login, register }

    /// Flags to trigger thrown errors for specific calls.
    var shouldFailLogin = false
    var shouldFailRegister = false
    /// Artificial latency applied before returning from calls.
    var delayNanoseconds: UInt64 = 0

    override init(session: URLSession? = nil) {
        try! super.init(session: session,
                        baseURL: URL(string: "https://example.com/api")!)
    }

    override func login(username: String, password: String) async throws {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        if shouldFailLogin { throw Failure.login }
    }

    override func register(username: String, email: String, password: String) async throws {
        if delayNanoseconds > 0 { try await Task.sleep(nanoseconds: delayNanoseconds) }
        if shouldFailRegister { throw Failure.register }
    }
}

/// Tests exercising ``LoginViewModel`` loading and validation behavior.
final class LoginViewModelTests: XCTestCase {
    /// Logging in should toggle ``isLoading`` so the UI can show a progress indicator.
    func testLoginTogglesLoadingState() async {
        let api = AuthMockAPI()
        api.delayNanoseconds = 50_000_000
        let vm = LoginViewModel(api: api)
        vm.username = "alice"
        vm.password = "password"
        let task = Task { await vm.login() }
        await Task.yield()
        XCTAssertTrue(vm.isLoading)
        await task.value
        XCTAssertFalse(vm.isLoading)
    }

    /// Validation failures should not set ``isLoading`` and must produce an error.
    func testLoginValidationFailure() async {
        let api = AuthMockAPI()
        let vm = LoginViewModel(api: api)
        vm.username = ""
        vm.password = "123"
        await vm.login()
        XCTAssertFalse(vm.isLoading)
        XCTAssertNotNil(vm.errorMessage)
    }

    /// Registration also toggles ``isLoading`` and resets it when complete.
    func testRegisterTogglesLoadingState() async {
        let api = AuthMockAPI()
        api.delayNanoseconds = 50_000_000
        let vm = LoginViewModel(api: api)
        vm.username = "alice"
        vm.email = "a@example.com"
        vm.password = "strongpassword"
        vm.isRegistering = true
        let task = Task { await vm.register() }
        await Task.yield()
        XCTAssertTrue(vm.isLoading)
        await task.value
        XCTAssertFalse(vm.isLoading)
    }
}
