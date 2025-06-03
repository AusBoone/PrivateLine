from flask_restful import Resource, reqparse
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import os
from models import User, Message
from app import db, app, socketio
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import json

# Fernet key for encryption
FERNET_KEY = os.environ.get('FERNET_KEY') or Fernet.generate_key()
cipher_suite = Fernet(FERNET_KEY)

# Request parser for user registration
user_parser = reqparse.RequestParser()
user_parser.add_argument('username', required=True, help="Username is required.")
user_parser.add_argument('email', required=True, help="Email is required.")
user_parser.add_argument('password', required=True, help="Password is required.")

# Request parser for messages
message_parser = reqparse.RequestParser()
message_parser.add_argument('content', required=True, help="Content is required.")

# Token serializer (legacy).  JWT is now used instead of this custom mechanism.
# s = Serializer(app.config['SECRET_KEY'], expires_in=3600)

# The previous implementation relied on a custom token_required decorator that
# used itsdangerous for token verification.  The project now leverages
# Flask-JWT-Extended, so authentication decorators below use @jwt_required.

"""
The private key is encrypted using AES-256 in CBC mode, 
with a key derived from the user's password using PBKDF2. 
The encrypted private key, salt, and IV are then 
sent to the user encoded in base64.
"""
class Register(Resource):
    """Create a new user and return the encrypted private key."""

    def post(self):
        # Parse the request data
        data = user_parser.parse_args()

        # Check if the user already exists
        user = User.query.filter_by(username=data['username']).first()
        if user:
            return {"message": "A user with that username already exists."}, 400

        # Hash the password
        hashed_password = generate_password_hash(data['password'], method='sha256')

        # Generate key pair
        private_key, public_key_pem = User.generate_key_pair()

        # Encrypt the private key with the user's password
        password = data['password'].encode()  # Encode the user's password as bytes
        salt = os.urandom(16)                 # Generate a random salt (16 bytes)
        
        # Key Derivation Function (KDF) to derive a cryptographic key from the password using PBKDF2 with HMAC and SHA-256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Use SHA-256 hash algorithm
            length=32,                  # Length of derived key (32 bytes)
            salt=salt,                  # Salt for the KDF
            iterations=100000,          # Number of iterations for the KDF
            backend=default_backend()   # Cryptographic backend
        )
        key = kdf.derive(password)  # Derive the key using the user's password
        
        iv = os.urandom(16)  # Generate a random initialization vector (IV) for AES encryption (16 bytes)
        
        # Create a cipher object using AES encryption in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()  # Create an encryptor object from the cipher
        
        # Create a padder object for PKCS7 padding
        padder = PKCS7(128).padder()
        
        # Pad the private key and convert it to bytes in PEM format
        padded_private_key = padder.update(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )) + padder.finalize()
        
        # Encrypt the padded private key
        encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()
        
        # Create a new user and add it to the database
        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password, public_key_pem=public_key_pem)
        db.session.add(new_user)  # Add the new user to the database session
        db.session.commit()       # Commit the database transaction
        
        # Send encrypted private key and encryption details to the user
        return {
            "message": "User registered successfully.",                            # Confirmation message
            "encrypted_private_key": b64encode(encrypted_private_key).decode(),     # Base64-encoded encrypted private key
            "salt": b64encode(salt).decode(),                                      # Base64-encoded salt
            "iv": b64encode(iv).decode()                                           # Base64-encoded IV
        }, 201

class Login(Resource):
    """Authenticate a user and return a JWT access token."""

    def post(self):
        data = request.get_json()

        # Query the database for the user with the given username
        user = User.query.filter_by(username=data['username']).first()

        if user and check_password_hash(user.password_hash, data['password']):
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200
        else:
            return {'message': 'Invalid username or password'}, 401


class PublicKey(Resource):
    """Return the public key for the given username."""

    @jwt_required()
    def get(self, username):
        """Fetch the PEM encoded public key for ``username``."""
        user = User.query.filter_by(username=username).first()
        if not user:
            return {"message": "User not found"}, 404
        return {"public_key": user.public_key_pem}

class Messages(Resource):
    """Retrieve or create encrypted chat messages."""

    # Retrieve all messages. Requires a valid JWT token.
    @jwt_required()
    def get(self):
        """Return decrypted messages for the authenticated user."""
        messages = Message.query.all()
        message_list = [
            {
                "id": msg.id,
                "content": cipher_suite.decrypt(msg.content.encode()).decode(),
                "timestamp": msg.timestamp,
                "user_id": msg.user_id,
            }
            for msg in messages
        ]
        return {"messages": message_list}

    # Send a new message. Rate limited via the limiter in app.py
    @jwt_required()
    def post(self):
        """Store an encrypted message and broadcast it to clients."""
        data = message_parser.parse_args()

        encrypted_content = cipher_suite.encrypt(data["content"].encode()).decode()

        current_user_id = get_jwt_identity()
        new_message = Message(content=encrypted_content, user_id=current_user_id)
        db.session.add(new_message)
        db.session.commit()

        # Broadcast the encrypted message to connected clients via WebSockets
        socketio.emit(
            "new_message",
            {"content": encrypted_content, "user_id": current_user_id},
        )

        return {"message": "Message sent successfully."}, 201
