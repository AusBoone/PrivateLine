import SwiftUI

/// Simple introductory screen explaining privacy benefits.
struct OnboardingView: View {
    @AppStorage("hasSeenOnboarding") private var hasSeen = false

    var body: some View {
        VStack(spacing: 20) {
            Text("Welcome to PrivateLine")
                .font(.largeTitle)
            Text("All messages are encrypted locally before being sent. Your privacy is our priority.")
                .multilineTextAlignment(.center)
                .padding()
            Button("Get Started") {
                hasSeen = true
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}

