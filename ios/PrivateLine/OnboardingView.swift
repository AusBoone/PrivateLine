import SwiftUI

/// Simple introductory screen explaining privacy benefits.
struct OnboardingView: View {
    @AppStorage("hasSeenOnboarding") private var hasSeen = false
    private let fingerprint = CryptoManager.fingerprint()

    var body: some View {
        VStack(spacing: 20) {
            Text("Welcome to PrivateLine")
                .font(.largeTitle)
            Text("All messages are encrypted locally before being sent. Your privacy is our priority.")
                .multilineTextAlignment(.center)
                .padding()
            if let fp = fingerprint {
                Text("Your key fingerprint: \(fp)")
                    .font(.footnote)
                    .padding()
            }
            Button("Get Started") {
                hasSeen = true
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}

