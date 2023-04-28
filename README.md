# PrivateLine
This project aims to create a privacy-focused, end-to-end encrypted messaging platform.

# Goal
The goal of this project is to build a secure messaging application that allows users to send and receive encrypted messages. The application utilizes a combination of asymmetric and symmetric encryption techniques to ensure message confidentiality.

# Overview
This secure messaging application consists of a frontend built with React and a backend built with Flask. The frontend handles user registration, login, message encryption/decryption, and message display. The backend handles user authentication, message storage, and key management.

# Features
- User registration and login
- Asymmetric encryption using RSA-OAEP for message exchange
- Symmetric encryption using AES-256 in CBC mode for private key storage
- Key derivation using PBKDF2
- Encrypted message storage
- Rate limiting on message sending
- JWT-based user authentication
- User account management interface

# Frontend
The frontend is built using React and consists of the following components:
1. LoginForm: Handles user login by sending a request to the backend for authentication.
2. RegisterForm: Handles user registration by sending user information to the backend, generating an RSA key pair, and storing the encrypted private key on the client-side.
3. Chat: Provides an interface for users to send and receive encrypted messages. The component also handles message encryption and decryption.
4. UserAccount: Displays the user account management interface.
5. App: Sets up the application's routing and includes the navigation bar.

# Backend
The backend is built using Flask and consists of the following resources:
1. Register: Handles user registration by saving user information, hashed passwords, and public keys to the database. It also returns the encrypted private key, salt, and IV to the frontend for storage.
2. Login: Handles user login by verifying the provided username and password, and returns a JWT access token if the credentials are valid.
3. Messages: Handles fetching and storing messages in the database. Messages are encrypted before storage and decrypted before sending them to the frontend.
The backend also includes rate limiting on message sending, JWT-based user authentication, and CORS configuration.

# Setup
To run the application, follow these steps:
1. Clone the repository.
2. Set up the frontend and backend by installing dependencies and starting the development servers.
3. Open a browser and navigate to the frontend's URL to use the application.
