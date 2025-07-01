# Android Client (Kotlin)

This directory contains a lightweight Android companion app for the PrivateLine
platform. The app mirrors the encryption workflow used by the iOS client and the
React frontend.

Features include:

* **RSA/OAEP encryption** using `APIService`
* **WebSocket** connectivity for real-time updates
* **Offline message cache** stored via `MessageStore`
* **User authentication** and registration flows
* **Attachment upload** prior to sending messages
* **Push notifications** delivered via Firebase Cloud Messaging (FCM)

The project intentionally stays small to demonstrate core functionality. It is a
starting point rather than a polished application.

## Getting Started

1. Install Android Studio and open the `android` folder as a project.
2. Update the base URL inside `APIService.kt` if your backend does not run on
   `localhost`.
3. Build and run the `app` module on an emulator or device.

You can also build from the command line:

```bash
./gradlew assembleDebug
```

If the wrapper JAR is missing (it is not stored in the repository),
run `gradle wrapper` once to generate it. This step is handled automatically
in CI so the project remains buildable.

## Local Message Storage

`MessageStore.kt` provides a minimal persistence layer for encrypted messages.
Messages are saved as JSON in the app's private files directory. Load the cache
when the application starts so conversations remain visible without a network
connection.

```
val cached = MessageStore.load(context)
// ... after fetching new messages
MessageStore.save(context, updatedMessages)
```

Only strings are stored because encryption is handled before the data reaches the
store. Failure to read or write the cache is silently ignored to avoid crashing
the app.

## Firebase Setup

Push notifications are handled using FCM. Add your `google-services.json` to the
`android/app` folder and ensure Firebase Messaging is enabled in your project.
On first launch the app will retrieve an FCM token and register it with the
backend's `/api/push-token` endpoint so notifications can be delivered when new
messages arrive.
