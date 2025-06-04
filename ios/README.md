# iOS Client (SwiftUI)

This directory contains a lightweight SwiftUI client for the PrivateLine backend. It now persists credentials in the Keychain with Face ID/Touch ID protection, caches messages for offline viewing and encrypts outgoing messages locally using CryptoKit.

## Getting Started

1. Open the `ios` folder in Xcode.
2. Modify `Info.plist` if your backend does not run on `localhost`. The keys `BackendBaseURL` and `WebSocketURL` control the REST and WebSocket endpoints.
3. Build and run the app in the iOS simulator.

After launching the app you will be greeted with a short onboarding flow describing encryption and privacy. You can then create an account or log in. Messages are loaded from local storage first and updated in real time via WebSockets.

The main interface uses a tab bar with sections for Chats and Settings. Credentials are protected with biometrics and you may revoke all server sessions from the Settings tab.

## New Features

- Optional dark mode toggle in Settings for a modern appearance.
- Push notification registration via `NotificationManager` so upcoming
  versions can alert users to new messages.

