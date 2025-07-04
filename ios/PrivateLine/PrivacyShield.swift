import SwiftUI
import Combine

/// Monitors application state and screen capture status to hide sensitive content.
///
/// When `obscured` becomes true a dark overlay should be displayed so the app
/// contents are not visible in the App Switcher or during screen recording.
final class PrivacyShield: ObservableObject {
    /// Indicates that the UI should be hidden behind an overlay.
    @Published var obscured: Bool = false

    private var cancellables: Set<AnyCancellable> = []

    init() {
        // Hide content whenever the app resigns active or enters background
        NotificationCenter.default.publisher(for: UIApplication.willResignActiveNotification)
            .merge(with: NotificationCenter.default.publisher(for: UIApplication.didEnterBackgroundNotification))
            .sink { [weak self] _ in self?.obscured = true }
            .store(in: &cancellables)

        // Reevaluate visibility when returning to the foreground
        NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)
            .sink { [weak self] _ in self?.updateCaptureState() }
            .store(in: &cancellables)

        // Update whenever screen capture starts or stops
        NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)
            .sink { [weak self] _ in self?.updateCaptureState() }
            .store(in: &cancellables)

        // Initial state based on current capture flag
        updateCaptureState()
    }

    /// Refresh the `obscured` property using the current screen capture status.
    private func updateCaptureState() {
        obscured = UIScreen.main.isCaptured || UIApplication.shared.applicationState != .active
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
