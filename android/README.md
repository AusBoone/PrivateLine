# Android Client (Kotlin)

This directory contains a lightweight Android companion app for the PrivateLine
platform. The app mirrors the encryption workflow used by the iOS client and the
React frontend.

Features include:

* **RSA/OAEP encryption** using `APIService`
* **WebSocket** connectivity for real-time updates
* **Offline message cache** stored via `MessageStore`
* **User authentication** and registration flows protected by biometrics
* **Attachment upload** prior to sending messages
* **Push notifications** delivered via Firebase Cloud Messaging (FCM)
* **Read receipts** allowing contacts to see when a message was opened
* **Ephemeral messages** automatically disappear after their expiration time
* **Group chat support** for encrypted conversations with multiple people
* **Settings screen** with dark mode and push notification toggle
* **Onboarding screen** displaying your public key fingerprint
* **TLS certificate pinning** to prevent man-in-the-middle attacks
* **Encrypted token storage** using the system KeyStore
* **Screen capture protection** preventing screenshots of sensitive chats

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

## Updating TLS Certificate Pin

The app verifies the server's identity using [certificate pinning]. Whenever the
backend TLS certificate changes you **must** update the pinned fingerprint or
connections will fail.

1. Run the shared helper script to fetch the new certificate and derive pins for
   both platforms:

   ```bash
   ./scripts/update_tls_fingerprints.sh api.example.com
   ```
2. Replace the value of `CERTIFICATE_SHA256` in `app/build.gradle` with the
   printed `ANDROID_FINGERPRINT`.
3. Insert the `IOS_FINGERPRINT` line into
   `ios/PrivateLine/Resources/server_fingerprints.txt`.
4. Commit the changes so CI can verify the pins. Rebuild the project so the new
   pin is embedded in `BuildConfig`.

[certificate pinning]: https://square.github.io/okhttp/features/certificate_pinner/

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

`MessageStore` now persists full `Message` objects so read receipts and
expiration timestamps survive app restarts. Encryption occurs before data
reaches the store, therefore the JSON on disk is still encrypted. Failure to
read or write the cache is silently ignored to avoid crashing the app.

## Group Key Persistence

`GroupKeyStore.kt` keeps per-group AES keys in `EncryptedSharedPreferences` so
that group conversations remain decryptable after restarting the app while
ensuring secrets are never written to disk in plaintext. `CryptoManager`
automatically falls back to this store when encrypting or decrypting group
messages if an in-memory key is missing. Call
`CryptoManager.removeGroupKey(id, context)` when leaving a group to erase the
persisted key from disk. All keys can be wiped at once using
`CryptoManager.clearAllGroupKeys(context)`. `GroupKeyStore.listGroupIds(context)`
returns the set of group ids currently saved which may be useful for preloading
keys during app startup.

The encrypted preferences are powered by the Jetpack Security library which
creates a master key stored in Android Keystore. This design prevents other
applications from reading the raw AES keys even on rooted devices.

`CryptoManager.preloadPersistedGroupKeys(context)` loads all saved keys into the
in-memory cache at once. Use it from your `Application` class to avoid disk
access when handling the first incoming message. Keys can be rotated at any time
with `CryptoManager.rotateGroupKey(id, context)` which returns the base64
representation of the newly generated secret for distribution to other group
members. To check whether a key already exists, call
`CryptoManager.hasGroupKey(id, context)` or `GroupKeyStore.contains(context, id)`.
All keys can be exported as base64 strings using `GroupKeyStore.exportAll(context)`
before migrating to a new device.

### Cross‑platform compatibility

Group keys use the same 256‑bit AES‑GCM format on Android, iOS and in the
React frontend. Keys retrieved from the backend can therefore be freely
exchanged between clients without reformatting. The Jetpack Security
encryption layer only affects local storage and does not change the value sent
over the network.

## Biometric Unlock

`TokenStore` saves the JWT token in `EncryptedSharedPreferences` so the value is
never written to disk in plaintext. Retrieval still requires Face or Touch ID
via the `BiometricPrompt` API. Call
`TokenStore.loadWithBiometrics(activity) { token -> ... }` when launching the
app to authenticate the user.

## Firebase Setup

Push notifications are handled using FCM. Add your `google-services.json` to the
`android/app` folder and ensure Firebase Messaging is enabled in your project.
On first launch the app will retrieve an FCM token and register it with the
backend's `/api/push-token` endpoint so notifications can be delivered when new
messages arrive.
