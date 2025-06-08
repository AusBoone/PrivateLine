# PrivateLine
This project aims to create a privacy-focused messaging platform. End-to-end encryption is now implemented across all clients: messages are encrypted locally before being transmitted.

# Goal
The goal of this project is to build a secure messaging application that allows users to send and receive encrypted messages. The application utilizes a combination of asymmetric and symmetric encryption techniques to ensure message confidentiality.

# Overview
This secure messaging application consists of a frontend built with React and a backend built with Flask. The frontend handles user registration, login, message encryption/decryption, and message display. The backend handles user authentication, message storage, and key management.

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
- Offline caching of messages on the iOS client
- Optional dark mode and push notification support on iOS

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
1. **Register**: Handles user registration by saving user information, hashed passwords, and public keys to the database. It also returns the encrypted private key, salt, and IV to the frontend for storage.
2. **Login**: Handles user login by verifying the provided username and password, and returns a JWT access token if the credentials are valid.
3. **Messages**: Handles fetching and storing messages in the database. Messages are encrypted before storage and decrypted before sending them to the frontend.
4. **RefreshToken**: Issues a new JWT for an authenticated user when called with a valid token.
5. **RevokeToken**: Revokes the current JWT so it can no longer be used.

The backend also includes rate limiting on message sending, JWT-based user authentication, and CORS configuration.

# Setup
To run the application, follow these steps:
1. Clone the repository.
2. Copy `.env.example` to `.env` and provide values for the following variables:
   * `JWT_SECRET_KEY` – key used for JWT signatures.
   * `AES_KEY` – base64 encoded 32 byte key used to encrypt persisted messages. A convenient way to generate one is `openssl rand -base64 32`.
   * Optional `DATABASE_URI` if you want to use a database other than the default SQLite file.
   * Optional `REDIS_URL` for persistent rate limiting storage.
   * Optional `SOCKETIO_ORIGINS` to restrict WebSocket origins.
   * Optional push notification settings: `APNS_CERT`, `APNS_TOPIC`,
     `VAPID_PRIVATE_KEY` and `VAPID_SUBJECT`.
3. Install backend dependencies with `pip install -r requirements.txt`.
4. Install frontend dependencies with `npm install` inside the `frontend` directory.
5. Start the backend with `python backend/app.py` and the frontend with `npm start`.
6. Open a browser and navigate to the frontend's URL to use the application.
7. After registering a user, persist the returned `encrypted_private_key`, `salt` and `nonce`. The React client stores these values in IndexedDB so the private key can be decrypted on login. The iOS client saves the same values securely in the Keychain.

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

- Update `Info.plist` so the `BackendBaseURL` and `WebSocketURL` keys point at
  your server if it does not run on `localhost`.
- Run the Swift package tests with
  `xcodebuild -scheme PrivateLine-Package test` or choose **Product → Test** in
  Xcode.
- To receive push notifications, start the backend with `APNS_CERT` and
  `APNS_TOPIC`. The app's `NotificationManager` will register its APNs token by
  calling `/api/push-token` after a user signs in.

## Push Notifications
The backend can notify offline clients via Apple Push Notification service (APNs)
and the Web Push protocol. To enable this feature you must provide additional
environment variables:

* `APNS_CERT` – path to the PEM certificate used for APNs.
* `APNS_TOPIC` – the bundle identifier of your iOS app.
* `VAPID_PRIVATE_KEY` – private key for Web Push messages.
* `VAPID_SUBJECT` – contact URI shown in Web Push claims.

Generate VAPID keys with `npx web-push generate-vapid-keys` and copy the
public key to `REACT_APP_VAPID_PUBLIC_KEY` for the React frontend. For APNs,
export your push notification certificate as a `.p12` file and convert it to PEM:

```bash
openssl pkcs12 -in cert.p12 -out apns.pem -nodes
```

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
(e.g. the `html` directory for Nginx). Ensure environment variables such as
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

