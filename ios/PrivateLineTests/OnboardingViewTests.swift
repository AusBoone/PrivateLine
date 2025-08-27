/*
 * OnboardingViewTests.swift - Unit tests for the onboarding flow.
 * Validates that users can navigate through pages and that the
 * `hasSeenOnboarding` flag persists when the flow is skipped or
 * completed.
 */
#if canImport(SwiftUI)
import XCTest
import SwiftUI
@testable import PrivateLine

/// Test suite covering navigation and persistence for ``OnboardingView``.
final class OnboardingViewTests: XCTestCase {
    /// Advancing pages should increment ``currentPage`` and stop at the last page.
    func testNavigationAdvancesPages() {
        var view = OnboardingView()
        XCTAssertEqual(view.currentPage, 0)
        view.goToNextPage()
        XCTAssertEqual(view.currentPage, 1)
        view.goToNextPage()
        XCTAssertEqual(view.currentPage, 2)
        // Attempting to advance beyond the last page should have no effect.
        view.goToNextPage()
        XCTAssertEqual(view.currentPage, 2)
    }

    /// Skipping onboarding should set ``hasSeenOnboarding`` so the flow does not reappear.
    func testSkipSetsHasSeenFlag() {
        var view = OnboardingView()
        view.hasSeen = false
        view.skip()
        XCTAssertTrue(view.hasSeen)
    }

    /// Completing onboarding via the final page should also persist the flag.
    func testCompletionSetsHasSeenFlag() {
        var view = OnboardingView()
        view.hasSeen = false
        view.completeOnboarding()
        XCTAssertTrue(view.hasSeen)
    }
}
#endif
