import SwiftUI

/// Simple introductory screen explaining privacy benefits.
struct OnboardingView: View {
    /// Tracks whether the onboarding screen has been dismissed.
    @AppStorage("hasSeenOnboarding") private var hasSeen = false
    /// Fingerprint of the user's public key shown for verification.
    private let fingerprint = CryptoManager.fingerprint()

    var body: some View {
        VStack(spacing: 20) {
            Text("Welcome to PrivateLine")
                .font(.largeTitle)
            Text("All messages are encrypted locally before being sent. Your privacy is our priority.")
                .multilineTextAlignment(.center)
                .padding()
            // Display the user's key fingerprint for verification
            if let fp = fingerprint {
                Text("Your key fingerprint: \(fp)")
                    .font(.footnote)
                    .padding()
            }
            // Dismiss the onboarding screen
            Button("Get Started") {
                hasSeen = true
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}

