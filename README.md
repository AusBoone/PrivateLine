# PrivateLine
This project aims to create a privacy-focused messaging platform. End-to-end encryption is now implemented across all clients: messages are encrypted locally before being transmitted.

# Goal
The goal of this project is to build a secure messaging application that allows users to send and receive encrypted messages. The application utilizes a combination of asymmetric and symmetric encryption techniques to ensure message confidentiality.

# Overview
This secure messaging application consists of a frontend built with React and a backend built with Flask. The frontend handles user registration, login, message encryption/decryption, and message display. The backend handles user authentication, message storage, and key management.
See [docs/architecture.md](docs/architecture.md) for a high-level overview of how the pieces fit together.

# Features
- User registration and login
- Asymmetric encryption using **RSA-OAEP** (4096-bit keys) for message exchange across all clients
- Symmetric encryption using **AES-256** in GCM mode for private key storage and message persistence
- Key derivation using **PBKDF2**
- Encrypted message storage
- Rate limiting on message sending
- JWT-based user authentication
- Token refresh and revocation endpoints for session management
- Real-time message delivery over WebSockets
- User account management interface
- Public key verification via QR codes
- Offline caching of messages on the iOS client
- Offline caching of messages on the React frontend
- Persisted group chat keys across all clients for offline decryption
- Optional dark mode and push notification support on iOS
- Ephemeral messages with automatic expiration handling
- Smooth animated chat interface for the React frontend
- Unread message count endpoint for quick status checks. Use ``GET /api/unread_count``
  to retrieve the total number of unread direct and group messages for the
  authenticated user.

## Ephemeral messages and offline caching

Messages can include an expiration timestamp. Expired messages are
automatically removed by a scheduled job on the backend and pruned from
the clients' local caches. Both the React and mobile clients store a small
history offline so conversations remain visible without network access.

# Frontend
The frontend is built using React and consists of the following components:
1. **LoginForm**: Handles user login by sending a request to the backend for authentication and decrypts the stored private key using the user's password.
2. **RegisterForm**: Handles user registration by sending user information to the backend, generating an RSA key pair, and storing the encrypted private key on the client-side.
3. **Chat**: Provides an interface for users to send and receive encrypted messages using RSA-OAEP.
4. **UserAccount**: Displays the user account management interface.
5. **App**: Sets up the application's routing, theme provider and navigation bar.

The interface uses the Material-UI component library. It supports a responsive layout with a permanent sidebar for conversations and a dark mode toggle.

# Backend
The backend is built using Flask and consists of the following resources:

An up-to-date OpenAPI specification can be found in [docs/openapi.yaml](docs/openapi.yaml). Run `python backend/generate_openapi.py` to regenerate the file after modifying the API.
1. **Register**: Handles user registration by saving user information, hashed passwords, and public keys to the database. It also returns the encrypted private key, salt, and IV to the frontend for storage.
2. **Login**: Handles user login by verifying the provided username and password, and returns a JWT access token if the credentials are valid.
3. **Messages**: Handles fetching and storing messages in the database. Messages
   are encrypted before storage and decrypted before sending them to the
   frontend. The retrieval endpoints (`/api/messages` and `/api/groups/<id>/messages`)
   accept optional `limit` and `offset` query parameters which default to 50 and
   0 respectively.
4. **RefreshToken**: Issues a new JWT for an authenticated user when called with a valid token.
5. **RevokeToken**: Revokes the current JWT so it can no longer be used.
6. **UnreadCount**: Returns the number of unread messages for the current user.

The backend also includes rate limiting on message sending, JWT-based user authentication, and CORS configuration.

# Setup
To run the application, follow these steps:
1. Clone the repository.
2. Copy `.env.example` to `.env` and provide values for the following variables:
   * `JWT_SECRET_KEY` – **required** key used for JWT signatures.
   * `AES_KEY` – base64 encoded 32 byte key used to encrypt persisted messages. A convenient way to generate one is `openssl rand -base64 32`.
   * Optional `DATABASE_URI` if you want to use a database other than the default SQLite file.
   * Optional `REDIS_URL` for persistent rate limiting and token blocklist storage.
   * Optional `CORS_ORIGINS` to restrict allowed origins for both REST and
     WebSocket connections.
   * Optional cookie security settings: `JWT_COOKIE_SECURE`,
     `JWT_COOKIE_SAMESITE` and `JWT_COOKIE_CSRF_PROTECT`.
   * Optional push notification settings: `APNS_CERT`, `APNS_TOPIC`,
    `APNS_USE_SANDBOX`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT` and
    `FCM_SERVER_KEY` for Android notifications.
   * Optional `SENTRY_DSN` to forward runtime errors to Sentry.
   * Optional `MAX_FILE_SIZE` to override the default 5&nbsp;MB upload limit.
   * Optional `CONTENT_SECURITY_POLICY` to customize the `Content-Security-Policy` header.
   * Optional `HSTS_ENABLED` to enable the `Strict-Transport-Security` header when served over HTTPS.
   * `ENCRYPTED_LOG_KEY` – base64 encoded 32 byte key to encrypt log files.
     Use `LOG_PATH` and `LOG_RETENTION_DAYS` to customize location and
     retention. A value of `0` disables rotation entirely.
   * Optional `LOGGING_DISABLED=true` to disable all logging when needed.
3. Install backend dependencies with `pip install -r requirements.txt`.
4. Install frontend dependencies with `npm install` inside the `frontend` directory.
5. Start the backend with `python backend/app.py` and the frontend with `npm start`.
6. Open a browser and navigate to the frontend's URL to use the application.
7. After registering a user, persist the returned `encrypted_private_key`, `salt` and `nonce`. The React client stores these values in IndexedDB so the private key can be decrypted on login. The iOS client saves the same values securely in the Keychain.

### Enabling Secure Cookies
Set `JWT_COOKIE_SECURE=true` in your environment when deploying behind HTTPS so authentication cookies are marked as secure. `JWT_COOKIE_SAMESITE` and `JWT_COOKIE_CSRF_PROTECT` can also be enabled for additional CSRF mitigation. The defaults remain development-friendly.

Uploaded files are limited to 5&nbsp;MB by default to prevent abuse. Set
`MAX_FILE_SIZE` in your environment to adjust the limit. Oversized uploads return
`413 Payload Too Large`.

### Security Headers
The backend adds several HTTP headers to harden responses:

* `Content-Security-Policy` restricts resource loading. Override with
  `CONTENT_SECURITY_POLICY` as needed.
* `X-Content-Type-Options: nosniff` prevents MIME type sniffing.
* `X-Frame-Options: DENY` disallows embedding the app in iframes.
* `Referrer-Policy: no-referrer` avoids leaking URLs.
* `Cache-Control: no-store` disables caching of API responses.
* When `HSTS_ENABLED=true`, a `Strict-Transport-Security` header enforces HTTPS.

## Docker

Docker images are provided for easier deployment. After copying `.env.example` to `.env` and setting the required values, build and start the containers with:

```bash
docker-compose up --build
```

When running with Docker, set `REACT_APP_API_URL=http://backend:5000` in your `.env` file so the React app can reach the Flask API container. The frontend will be available on port **3000** and the backend on port **5000**.

## Running Tests
Backend unit tests use **pytest**. Install the Python dependencies first:

```bash
pip install -r requirements.txt
```

Then run all backend tests from the repository root:

```bash
pytest
```

Frontend tests are written with **Jest**. Install the Node dependencies inside
the `frontend` directory and run the tests with:

```bash
cd frontend
npm install
npm test
```

The tests exercise the Flask API endpoints as well as the React components.

## iOS Client
A minimal SwiftUI client is located in the `ios/` directory. See
[ios/README.md](ios/README.md) for detailed setup instructions.

- Update `ios/PrivateLine/Resources/Config/Info.plist` so the `BackendBaseURL` and `WebSocketURL` keys point at
  your server if it does not run on `localhost`.
- Run the Swift package tests with
  `xcodebuild -scheme PrivateLine-Package test` or choose **Product → Test** in
  Xcode.
- To receive push notifications, start the backend with `APNS_CERT` and
  `APNS_TOPIC`. The app's `NotificationManager` will register its APNs token by
  calling `/api/push-token` after a user signs in.
- A privacy shield overlays the interface when the app is backgrounded or being
  recorded so chats are not visible in the app switcher.

## Android Client
A small Kotlin client lives in the `android/` directory. It mirrors the
iOS networking layer and saves encrypted messages locally using `MessageStore`.
Open the folder in Android Studio and run `./gradlew assembleDebug` to verify
the skeleton builds. If the Gradle wrapper JAR is missing, run `gradle wrapper`
first to generate it. See [android/README.md](android/README.md) for details.
All activities inherit from `SecureActivity` which applies the system
`FLAG_SECURE` window attribute so chats cannot be captured in screenshots.

### Release Process

To create a production APK run:

```bash
cd android
./gradlew assembleRelease
```

For iOS builds execute:

```bash
cd ios
xcodebuild -scheme PrivateLine-Package -configuration Release
```

The OpenAPI specification is regenerated during CI to ensure the mobile clients
remain in sync with the backend.

## Push Notifications
The backend can notify offline clients via Apple Push Notification service (APNs),
Firebase Cloud Messaging (FCM) and the Web Push protocol. To enable this feature
you must provide additional
environment variables:

* `APNS_CERT` – path to the PEM certificate used for APNs.
* `APNS_TOPIC` – the bundle identifier of your iOS app.
* `APNS_USE_SANDBOX` – set to `false` when using production APNs.
* `VAPID_PRIVATE_KEY` – private key for Web Push messages.
* `VAPID_SUBJECT` – contact URI shown in Web Push claims.
* `FCM_SERVER_KEY` – server key issued by FCM for Android pushes.

Example `.env` entries:

```bash
APNS_CERT=apns.pem
APNS_TOPIC=com.example.PrivateLine
APNS_USE_SANDBOX=true
VAPID_PRIVATE_KEY=vapid_private.pem
VAPID_SUBJECT=mailto:admin@example.com
```

Generate VAPID keys with `npx web-push generate-vapid-keys` and copy the
public key to `REACT_APP_VAPID_PUBLIC_KEY` for the React frontend. For APNs,
export your push notification certificate as a `.p12` file and convert it to PEM:

```bash
openssl pkcs12 -in cert.p12 -out apns.pem -nodes
```

When deploying with Docker, mount your certificate files into the backend
container and reference them in `.env`. A `docker-compose.yml` snippet looks
like:

```yaml
services:
  backend:
    volumes:
      - ./apns.pem:/app/apns.pem:ro
      - ./vapid_private.pem:/app/vapid_private.pem:ro
```

Then set `APNS_CERT=/app/apns.pem`, `APNS_USE_SANDBOX=true` (or `false` for
production) and `VAPID_PRIVATE_KEY=/app/vapid_private.pem` in your environment
file.

After authentication each client calls `POST /api/push-token` with its push
token and platform (`ios` or `web`). These tokens are stored in the database and
used by `send_push_notifications` to deliver alerts whenever a new message is
created.

## Production Deployment
Running the backend with the built-in Flask development server is not recommended for production.
Use Gunicorn together with an async worker so Socket.IO connections work properly.
Example commands using **eventlet** or **gevent**:

```bash
# Eventlet worker
pip install gunicorn eventlet
gunicorn -k eventlet -w 1 backend.app:app

# Or gevent worker
pip install gunicorn gevent
gunicorn -k gevent -w 1 backend.app:app
```

Before starting the server, apply database migrations so your schema is up to date. If the
`migrations/` directory has not been created yet, initialize it first:

```bash
flask db init   # only needed once
flask db upgrade
```

### Serving the React build
Build the frontend and serve the static files with your web server:

```bash
cd frontend
REACT_APP_API_URL=https://api.example.com npm run build
```

Copy the contents of `frontend/build` to the directory served by your HTTP server
(e.g. the `html` directory for Nginx). Ensure **required** environment variables such as
`JWT_SECRET_KEY`, `AES_KEY` and `DATABASE_URI` are configured on the backend in
production.


### TLS Termination
For HTTPS deployments, place a reverse proxy such as Nginx in front of the application.
Terminate TLS at the proxy and forward traffic to Gunicorn on port 5000.
If running with Docker, you can use an nginx-proxy setup with the LetsEncrypt companion
container for automatic certificate management.

### Example production setup on DigitalOcean

One approach for hosting is a small **DigitalOcean Droplet** running Docker
and Docker Compose. After provisioning an Ubuntu droplet and installing the
Docker tooling, copy `.env.example` to `.env` and set at least
`POSTGRES_PASSWORD`, `JWT_SECRET_KEY` and `AES_KEY`. Optionally provide
`SENTRY_DSN` for error reporting.

Deploy the stack using the production compose file:

```bash
docker compose -f docker-compose.prod.yml up -d
```

Logs from the services are sent to the address defined in the `gelf` logging
driver. Adjust `logcollector` in `docker-compose.prod.yml` to point at your
aggregator (e.g. Graylog or Logstash).

## Key Verification

The **User Account** screen shows your public key fingerprint and a QR code that
can be shared with contacts. When adding a new contact, scan their QR code and
compare fingerprints. Matching fingerprints ensure end-to-end encryption is not
being intercepted.

## Future Improvements

Several areas could further enhance PrivateLine:

- **Forward secrecy**: adopting a double ratchet protocol so message keys
  rotate frequently would reduce the impact of any single compromised key.
- **Expanded test coverage**: adding tests for failure modes like file uploads
  and downloads would catch regressions earlier.

