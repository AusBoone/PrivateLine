# Architecture Overview

The PrivateLine project is split into three main components:

* **backend/** – Flask API providing REST endpoints, WebSocket events and the
  database models. All sensitive data is encrypted at rest using AES-GCM.
* **frontend/** – React application implementing the chat UI. Messages are
  encrypted in the browser and cached locally for offline use.
* **ios/** and **android/** – Mobile clients sharing the same API. The iOS app
  is written in SwiftUI while the Android version uses Kotlin.

Messages flow from the frontend or mobile clients through the Flask API. The
backend only sees ciphertext and stores it with a second layer of AES
encryption. WebSocket connections relay new messages in real time. The database
schema is defined in `backend/models.py`.

```
[React/iOS/Android] --encrypted--> [Flask API] --AES--> [Database]
```

Each client verifies public key fingerprints out-of-band to prevent
man-in-the-middle attacks. See the User Account screen for QR code sharing.
