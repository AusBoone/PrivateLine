/*
 * OnboardingView.swift
 * Multi-step onboarding flow explaining app features, privacy guarantees,
 * and key backup. Implemented as a paged ``TabView`` to guide users through
 * three screens before landing in the main app. Users may copy their key
 * fingerprint for backup and can skip the flow entirely.
 */
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// First-run experience for new installs.
///
/// The view presents three pages in a swipeable ``TabView``:
///   1. Features overview.
///   2. Privacy commitment.
///   3. Key backup with fingerprint copy.
///
/// Users can advance via "Next" buttons, copy their fingerprint, or skip the
/// flow. Completing or skipping persists ``hasSeenOnboarding`` so the flow
/// only appears once.
struct OnboardingView: View {
    /// Persisted flag tracking whether onboarding was shown.
    @AppStorage("hasSeenOnboarding") var hasSeen = false
    /// Currently selected onboarding page. ``internal`` for unit tests.
    @State var currentPage = 0
    /// Fingerprint of the user's public key displayed on the backup page.
    private let fingerprint = CryptoManager.fingerprint()

    /// Advance to the next onboarding page without exceeding bounds.
    func goToNextPage() {
        if currentPage < 2 { currentPage += 1 }
    }

    /// Mark onboarding as complete and persist the flag.
    func completeOnboarding() { hasSeen = true }

    /// Skip onboarding entirely.
    func skip() { hasSeen = true }

    var body: some View {
        VStack {
            TabView(selection: $currentPage) {
                featurePage.tag(0)
                privacyPage.tag(1)
                backupPage.tag(2)
            }
            .tabViewStyle(PageTabViewStyle(indexDisplayMode: .always))
        }
        // "Skip" option visible on all pages
        .overlay(alignment: .topTrailing) {
            Button("Skip") { skip() }
                .padding()
        }
        .padding()
    }

    /// First page highlighting app features.
    private var featurePage: some View {
        VStack(spacing: 20) {
            Text("Welcome to PrivateLine")
                .font(.largeTitle)
            Text("Securely chat with end-to-end encryption and self-destructing messages.")
                .multilineTextAlignment(.center)
            Button("Next") { goToNextPage() }
                .buttonStyle(.borderedProminent)
        }
    }

    /// Second page outlining privacy philosophy.
    private var privacyPage: some View {
        VStack(spacing: 20) {
            Text("Your Privacy")
                .font(.title)
            Text("Messages are encrypted locally. We never see your conversations.")
                .multilineTextAlignment(.center)
            Button("Next") { goToNextPage() }
                .buttonStyle(.borderedProminent)
        }
    }

    /// Final page encouraging key backup and offering fingerprint copy.
    private var backupPage: some View {
        VStack(spacing: 20) {
            Text("Backup Your Key")
                .font(.title)
            if let fp = fingerprint {
                Text("Fingerprint: \(fp)")
                    .font(.footnote)
                    .multilineTextAlignment(.center)
#if canImport(UIKit)
                Button("Copy fingerprint") { UIPasteboard.general.string = fp }
                    .buttonStyle(.bordered)
#endif
            } else {
                // Should not normally occur but handle missing key gracefully
                Text("Fingerprint unavailable")
                    .font(.footnote)
            }
            Button("Get Started") { completeOnboarding() }
                .buttonStyle(.borderedProminent)
        }
    }
}

