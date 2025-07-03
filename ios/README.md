# iOS Client (SwiftUI)

This directory contains a lightweight SwiftUI client for the PrivateLine backend. It now persists credentials in the Keychain with Face ID/Touch ID protection, caches messages for offline viewing and encrypts outgoing messages locally using CryptoKit.
See the [project README](../README.md) for backend configuration and environment
variables.

## Getting Started

1. Open the `ios` folder in Xcode.
2. Open `Resources/Config/Info.plist` and change the string values of `BackendBaseURL` and
   `WebSocketURL` if your backend does not run on `localhost`.
3. Build and run the app in the iOS simulator.

After launching the app you will be greeted with a short onboarding flow describing encryption and privacy. You can then create an account or log in. Messages are loaded from local storage first and updated in real time via WebSockets.

The main interface uses a tab bar with sections for Chats and Settings. Credentials are protected with biometrics and you may revoke all server sessions from the Settings tab.

## Running Tests

Run the Swift package tests with:

```bash
xcodebuild -scheme PrivateLine-Package test
```

You can also open the project in Xcode and choose **Product → Test** from the menu.

## New Features

- Optional dark mode toggle in Settings for a modern appearance.
- Push notification registration via `NotificationManager` so upcoming
  versions can alert users to new messages.
- Support for ephemeral messages. When composing a chat you can select an
  expiration time and messages are automatically hidden locally once that time
  passes.
- Settings now include a switch to enable or disable push notifications at any
  time.
- Group chat keys now persist securely in the Keychain so encrypted messages can
  be read after restarting the app. Keys can be listed or removed via
  `CryptoManager` helper functions.

## Push Notifications

`NotificationManager` requests permission from `UNUserNotificationCenter` when
the app launches. On success `UIApplication.shared.registerForRemoteNotifications()`
obtains the APNs device token which is forwarded from `AppDelegate` to
`NotificationManager.registerDeviceToken`. That method sends the token in
hexadecimal form to the backend's `/api/push-token` endpoint using the logged-in
user's bearer token.

For notifications to be delivered the backend must be started with two
environment variables:

* `APNS_CERT` – path to your `.pem` APNs certificate.
* `APNS_TOPIC` – the bundle identifier of this app.

With these set, you can test push notifications by sending a message to a user
while the app is in the background on a device or simulator that supports push
delivery. The backend will use the stored token to send an alert via APNs.

## Test Suite Overview

The Swift package contains a small set of unit tests which can be executed on
macOS or Linux using `swift test` (or `xcodebuild` on macOS). Each test file
focuses on a different component:

- `APIServicesTests` exercises the login flow and message APIs using mocked
  network responses.
- `CryptoManagerTests` verifies symmetric encryption, group key handling and
  RSA helpers.
- `WebSocketServiceTests` ensures the WebSocket wrapper connects and disconnects
  correctly.
- `MessageStoreTests` checks that cached messages persist to disk.
- `PinningDelegateTests` validates the certificate pinning logic used when
  communicating with the backend.

Running these tests regularly helps ensure the iOS client continues to work
correctly as new features are added.

