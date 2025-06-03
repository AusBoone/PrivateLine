# PrivateLine
This project aims to create a privacy-focused, end-to-end encrypted messaging platform.

# Goal
The goal of this project is to build a secure messaging application that allows users to send and receive encrypted messages. The application utilizes a combination of asymmetric and symmetric encryption techniques to ensure message confidentiality.

# Overview
This secure messaging application consists of a frontend built with React and a backend built with Flask. The frontend handles user registration, login, message encryption/decryption, and message display. The backend handles user authentication, message storage, and key management.

# Features
- User registration and login
- Asymmetric encryption using **RSA-OAEP** for message exchange
- Client-side private key storage
- Key derivation using **PBKDF2**
- Encrypted message storage
- Rate limiting on message sending
- JWT-based user authentication
- Real-time message delivery over WebSockets
- User account management interface
- Automatic redirects after registration and login

# Frontend
The frontend is built using React and consists of the following components:
1. **LoginForm**: Handles user login by sending a request to the backend for authentication and redirects to the chat interface upon success.
2. **RegisterForm**: Handles user registration by generating an RSA key pair, sending the public key to the backend, storing the private key on the client, and then redirecting to the login page.
3. **Chat**: Provides an interface for users to send and receive encrypted messages. The component also handles message encryption and decryption.
4. **UserAccount**: Displays the user account management interface.
5. **App**: Sets up the application's routing and includes the navigation bar.

# Backend
The backend is built using Flask and consists of the following resources:
1. **Register**: Handles user registration by saving user information, hashed passwords, and the provided public key to the database. The private key remains on the client.
2. **Login**: Handles user login by verifying the provided username and password, and returns a JWT access token if the credentials are valid.
3. **Messages**: Handles fetching and storing messages in the database. Messages are stored exactly as submitted by clients (already encrypted).
The backend also includes rate limiting on message sending, JWT-based user authentication, and CORS configuration.

# Setup
To run the application, follow these steps:
1. Clone the repository.
2. Copy `.env.example` to `.env` and provide values for `JWT_SECRET_KEY` and optional `DATABASE_URI`.
3. Install backend dependencies with `pip install -r backend/requirements.txt`.
4. (Optional) install frontend dependencies in `frontend` if using Node.
5. Start the backend with `python backend/app.py` and the frontend with your preferred React tooling.
6. Open a browser and navigate to the frontend's URL to use the application.
