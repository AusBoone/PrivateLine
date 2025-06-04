# iOS Client (SwiftUI)

This directory contains a lightweight SwiftUI client for the PrivateLine backend. It now persists credentials in the Keychain, supports registration and displays messages in real time via WebSockets.

## Getting Started

1. Open the `ios` folder in Xcode.
2. Modify `Info.plist` if your backend does not run on `localhost`. The keys `BackendBaseURL` and `WebSocketURL` control the REST and WebSocket endpoints.
3. Build and run the app in the iOS simulator.

After launching the app you can create an account or log in. Messages are fetched using async/await and appear instantly when delivered over the WebSocket connection.
