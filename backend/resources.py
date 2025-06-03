from flask_restful import Resource, reqparse
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os
from .models import User, Message
from .app import db, app, socketio
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

# AES-GCM key for encrypting stored messages
_aes_key_env = os.environ.get('AES_KEY')
if _aes_key_env:
    AES_KEY = b64decode(_aes_key_env)
else:
    AES_KEY = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(AES_KEY)


# Request parser for messages
message_parser = reqparse.RequestParser()
message_parser.add_argument(
    'content', required=True, location='form', help="Content is required."
)

# Token serializer (legacy).  JWT is now used instead of this custom mechanism.
# s = Serializer(app.config['SECRET_KEY'], expires_in=3600)

# The previous implementation relied on a custom token_required decorator that
# used itsdangerous for token verification.  The project now leverages
# Flask-JWT-Extended, so authentication decorators below use @jwt_required.

"""
The private key is encrypted using AES-256 in GCM mode,
with a key derived from the user's password using PBKDF2.
The encrypted private key, salt, and nonce are then
sent to the user encoded in base64.
"""
class Register(Resource):
    """Create a new user and return the encrypted private key."""

    def post(self):
        # Accept both JSON and form-encoded input
        data = request.get_json(silent=True)
        if not data:
            data = request.form.to_dict()

        required = {'username', 'email', 'password'}
        if not data or not required <= data.keys():
            return {"message": "Username, email and password are required."}, 400

        # Check if the user already exists
        user = User.query.filter_by(username=data['username']).first()
        if user:
            return {"message": "A user with that username already exists."}, 400

        # Hash the password
        # Use PBKDF2 with SHA-256 for password hashing
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

        # Generate key pair
        private_key, public_key_pem = User.generate_key_pair()

        # Encrypt the private key with the user's password using AES-GCM
        password = data['password'].encode()  # Encode the user's password as bytes
        salt = os.urandom(16)                 # Generate a random salt (16 bytes)

        # Key Derivation Function (KDF) to derive a cryptographic key from the password using PBKDF2 with HMAC and SHA-256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Use SHA-256 hash algorithm
            length=32,                  # Length of derived key (32 bytes)
            salt=salt,                  # Salt for the KDF
            iterations=200000,          # Number of iterations for the KDF
            backend=default_backend()   # Cryptographic backend
        )
        key = kdf.derive(password)  # Derive the key using the user's password

        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        aes = AESGCM(key)

        private_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )

        encrypted_private_key = aes.encrypt(nonce, private_bytes, None)
        
        # Create a new user and add it to the database
        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password, public_key_pem=public_key_pem)
        db.session.add(new_user)  # Add the new user to the database session
        db.session.commit()       # Commit the database transaction
        
        # Send encrypted private key and encryption details to the user
        return {
            "message": "User registered successfully.",                            # Confirmation message
            "encrypted_private_key": b64encode(encrypted_private_key).decode(),     # Base64-encoded encrypted private key
            "salt": b64encode(salt).decode(),                                      # Base64-encoded salt
            "nonce": b64encode(nonce).decode()                                           # Base64-encoded nonce
        }, 201

class Login(Resource):
    """Authenticate a user and return a JWT access token."""

    def post(self):
        data = request.get_json()

        # Query the database for the user with the given username
        user = User.query.filter_by(username=data['username']).first()

        if user and check_password_hash(user.password_hash, data['password']):
            access_token = create_access_token(identity=str(user.id))
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
        message_list = []
        for msg in messages:
            nonce = b64decode(msg.nonce)
            ciphertext = b64decode(msg.content)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
            message_list.append({
                "id": msg.id,
                "content": plaintext,
                "timestamp": msg.timestamp.isoformat(),
                "user_id": msg.user_id,
            })
        return {"messages": message_list}

    # Send a new message. Rate limited via the limiter in app.py
    @jwt_required()
    def post(self):
        """Store an encrypted message and broadcast it to clients."""
        data = message_parser.parse_args()

        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data["content"].encode(), None)
        encrypted_content = b64encode(ciphertext).decode()
        nonce_b64 = b64encode(nonce).decode()

        current_user_id = int(get_jwt_identity())
        new_message = Message(content=encrypted_content, nonce=nonce_b64, user_id=current_user_id)
        db.session.add(new_message)
        db.session.commit()

        # Broadcast the encrypted message to connected clients via WebSockets
        socketio.emit(
            "new_message",
            {"content": encrypted_content, "user_id": current_user_id},
        )

        return {"message": "Message sent successfully."}, 201


class AccountSettings(Resource):
    """Update the authenticated user's account information."""

    @jwt_required()
    def put(self):
        data = request.get_json() or {}
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        updated = False

        new_email = data.get("email")
        if new_email:
            user.email = new_email
            updated = True

        current_pw = data.get("currentPassword")
        new_pw = data.get("newPassword")
        if current_pw and new_pw:
            if check_password_hash(user.password_hash, current_pw):
                # Rehash the new password using PBKDF2 with SHA-256
                user.password_hash = generate_password_hash(new_pw, method="pbkdf2:sha256")
                updated = True
            else:
                return {"message": "Current password is incorrect."}, 400

        if not updated:
            return {"message": "No account changes provided."}, 400

        db.session.commit()
        return {"message": "Account updated."}, 200
