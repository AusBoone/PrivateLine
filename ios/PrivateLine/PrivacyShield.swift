// PrivacyShield.swift
//
// Provides an overlay that hides sensitive content when the application is not
// active or when screen recording is detected. The session lock now requires
// biometric or passcode authentication via ``LocalAuthentication`` before the
// overlay is dismissed, preventing unauthorized access when returning to the
// app.
import SwiftUI
import Combine
import LocalAuthentication

/// Monitors application state and screen capture status to hide sensitive content.
///
/// When `obscured` becomes true a dark overlay should be displayed so the app
/// contents are not visible in the App Switcher or during screen recording.
/// Tracks application lifecycle events to protect sensitive content and enforce
/// a session lock when the app returns from the background.
///
/// The shield hides the UI whenever the app becomes inactive or when screen
/// capture is detected. Upon re-entering the foreground the user must
/// re-authenticate via biometrics or passcode before the overlay disappears.
final class PrivacyShield: ObservableObject {
    /// Indicates that the UI should be hidden behind an overlay.
    @Published var obscured: Bool = false
    /// Set when the most recent authentication attempt failed so callers can
    /// present a helpful error message.
    @Published var authFailed: Bool = false

    /// Factory providing ``LAContext`` instances. Exposed for unit testing so
    /// tests can inject mocked contexts that simulate success or failure.
    private let contextProvider: () -> LAContext
    /// Tracks Combine subscriptions for lifecycle notifications.
    private var cancellables: Set<AnyCancellable> = []
    /// True when the app moved to the background and the user must
    /// authenticate before content becomes visible again.
    private var needsAuthentication = false

    /// Create a new ``PrivacyShield``.
    /// - Parameter contextProvider: Closure returning a fresh ``LAContext``. If
    ///   omitted a default instance is created. Tests provide custom closures to
    ///   control authentication outcomes.
    init(contextProvider: @escaping () -> LAContext = { LAContext() }) {
        self.contextProvider = contextProvider

        // Hide content whenever the app resigns active or enters background.
        NotificationCenter.default.publisher(for: UIApplication.willResignActiveNotification)
            .merge(with: NotificationCenter.default.publisher(for: UIApplication.didEnterBackgroundNotification))
            .sink { [weak self] _ in
                // Mark that re-authentication is required and obscure UI.
                self?.needsAuthentication = true
                self?.obscured = true
            }
            .store(in: &cancellables)

        // When returning to the foreground request authentication before
        // clearing the overlay.
        NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)
            .sink { [weak self] _ in self?.authenticateIfNeeded() }
            .store(in: &cancellables)

        // Update whenever screen capture starts or stops.
        NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)
            .sink { [weak self] _ in self?.updateCaptureState() }
            .store(in: &cancellables)

        // Initial state based on current capture flag.
        updateCaptureState()
    }

    /// Attempt to unlock the session if required. On success the overlay is
    /// removed; on failure the UI remains obscured and an error flag is raised.
    func authenticateIfNeeded() {
        guard needsAuthentication else {
            updateCaptureState()
            return
        }

        let context = contextProvider()
        // Reason displayed by the system authentication dialog.
        let reason = "Authenticate to unlock PrivateLine"
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] success, _ in
                DispatchQueue.main.async {
                    if success {
                        // Authentication succeeded: allow content to become visible.
                        self?.needsAuthentication = false
                        self?.authFailed = false
                        self?.updateCaptureState()
                    } else {
                        // Failure keeps the overlay visible until user retries.
                        self?.authFailed = true
                        self?.obscured = true
                    }
                }
            }
        } else {
            // Device cannot evaluate policy; treat as failure.
            authFailed = true
            obscured = true
        }
    }

    /// Allow UI layer to retry authentication after a failure.
    func retryAuthentication() {
        authenticateIfNeeded()
    }

    /// Refresh the `obscured` property using the current screen capture status
    /// while respecting the session lock requirement.
    private func updateCaptureState() {
        if needsAuthentication {
            obscured = true
        } else {
            obscured = UIScreen.main.isCaptured || UIApplication.shared.applicationState != .active
        }
    }
}

/// Modifier that overlays a black screen while the associated shield is obscured.
struct PrivacyOverlay: ViewModifier {
    @ObservedObject var shield: PrivacyShield

    func body(content: Content) -> some View {
        content.overlay(
            Group {
                if shield.obscured {
                    Color.black.ignoresSafeArea()
                }
            }
        )
    }
}

extension View {
    /// Attach a privacy overlay driven by the provided ``PrivacyShield``.
    func privacyOverlay(shield: PrivacyShield) -> some View {
        modifier(PrivacyOverlay(shield: shield))
    }
}
