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
from .models import (
    User,
    Message,
    PinnedKey,
    Group,
    GroupMember,
    File,
)
from .app import db, app, socketio, token_blocklist
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)

# AES-GCM key for encrypting stored messages
_aes_key_env = os.environ.get("AES_KEY")
if not _aes_key_env:
    app.logger.error("AES_KEY environment variable not set; cannot decrypt stored messages.")
    raise RuntimeError("AES_KEY environment variable is required for encryption")
AES_KEY = b64decode(_aes_key_env)
aesgcm = AESGCM(AES_KEY)


# Request parser for messages
message_parser = reqparse.RequestParser()
message_parser.add_argument(
    'content', required=True, location='form', help="Content is required."
)
message_parser.add_argument(
    'recipient', required=True, location='form', help="Recipient username is required."
)

# Parser used when posting to a group
group_message_parser = reqparse.RequestParser()
group_message_parser.add_argument(
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

        if len(data['username']) > 64 or len(data['email']) > 120:
            return {"message": "Username or email too long."}, 400
        if '@' not in data['email']:
            return {"message": "Invalid email address."}, 400

        # Check if the user already exists
        user = User.query.filter_by(username=data['username']).first()
        if user:
            return {"message": "A user with that username already exists."}, 400

        if len(data['password']) < 6:
            return {"message": "Password must be at least 6 characters."}, 400

        # Hash the password
        # Use PBKDF2 with SHA-256 for password hashing
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

        # Generate key pair
        private_key, public_key_pem = User.generate_key_pair()
        # Fingerprint of the public key to allow out-of-band verification
        from cryptography.hazmat.primitives.serialization import PublicFormat
        import hashlib
        fingerprint = hashlib.sha256(
            private_key.public_key().public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()

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
        new_user = User(
            username=data['username'],
            email=data['email'],
            password_hash=hashed_password,
            public_key_pem=public_key_pem,
        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception:
            app.logger.exception("Failed to register user")
            db.session.rollback()
            return {"message": "Registration failed."}, 500
        
        # Send encrypted private key and encryption details to the user
        return {
            "message": "User registered successfully.",  # Confirmation message
            "encrypted_private_key": b64encode(encrypted_private_key).decode(),  # Base64-encoded encrypted private key
            "salt": b64encode(salt).decode(),           # Base64-encoded salt
            "nonce": b64encode(nonce).decode(),         # Base64-encoded nonce
            "fingerprint": fingerprint,
        }, 201

class Login(Resource):
    """Authenticate a user and return a JWT access token."""

    def post(self):
        data = request.get_json() or {}

        if 'username' not in data or 'password' not in data:
            return {'message': 'Username and password are required.'}, 400

        # Query the database for the user with the given username
        user = User.query.filter_by(username=data['username']).first()

        if user and check_password_hash(user.password_hash, data['password']):
            access_token = create_access_token(identity=str(user.id))
            return {'access_token': access_token}, 200
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
        """Return base64-encoded ciphertext for the authenticated user."""
        from sqlalchemy import or_

        current_user_id = int(get_jwt_identity())
        messages = Message.query.filter(
            or_(
                Message.sender_id == current_user_id,
                Message.recipient_id == current_user_id,
            )
        ).all()
        message_list = []
        for msg in messages:
            nonce = b64decode(msg.nonce)
            ciphertext = b64decode(msg.content)
            # Decrypt the layer of server-side encryption to obtain the
            # client-provided ciphertext, then re-encode it for transport.
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            plaintext_b64 = b64encode(plaintext_bytes).decode()
            message_list.append({
                "id": msg.id,
                "content": plaintext_b64,
                "timestamp": msg.timestamp.isoformat(),
                "sender_id": msg.sender_id,
                "recipient_id": msg.recipient_id,
            })
        return {"messages": message_list}

    # Send a new message. Rate limited via the limiter in app.py
    @jwt_required()
    def post(self):
        """Store an encrypted message and broadcast it to clients."""
        data = message_parser.parse_args()

        if len(data['content']) > 2000:
            return {"message": "Message too long."}, 400

        recipient = User.query.filter_by(username=data['recipient']).first()
        if not recipient:
            return {"message": "Recipient not found."}, 404

        # The client sends base64 encoded ciphertext. Decode it before applying
        # server-side encryption for storage.
        try:
            client_ciphertext = b64decode(data["content"], validate=True)
        except Exception:
            return {"message": "Invalid base64 content."}, 400

        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, client_ciphertext, None)
        encrypted_content = b64encode(ciphertext).decode()
        nonce_b64 = b64encode(nonce).decode()

        current_user_id = int(get_jwt_identity())
        new_message = Message(
            content=encrypted_content,
            nonce=nonce_b64,
            user_id=current_user_id,
            sender_id=current_user_id,
            recipient_id=recipient.id,
        )
        try:
            db.session.add(new_message)
            db.session.commit()
        except Exception:
            app.logger.exception("Failed to store message")
            db.session.rollback()
            return {"message": "Failed to store message."}, 500

        # Broadcast the encrypted message to connected clients via WebSockets
        socketio.emit(
            "new_message",
            {
                "content": data["content"],
                "sender_id": current_user_id,
                "recipient_id": recipient.id,
            },
            to=str(recipient.id),
        )

        return {"message": "Message sent successfully."}, 201


class PinnedKeys(Resource):
    """Manage pinned key fingerprints for the authenticated user."""

    @jwt_required()
    def get(self):
        user_id = int(get_jwt_identity())
        keys = PinnedKey.query.filter_by(user_id=user_id).all()
        return {
            "pinned_keys": [{"username": k.username, "fingerprint": k.fingerprint} for k in keys]
        }

    @jwt_required()
    def post(self):
        data = request.get_json(silent=True) or request.form.to_dict()
        if not data or "username" not in data or "fingerprint" not in data:
            return {"message": "Username and fingerprint are required."}, 400
        user_id = int(get_jwt_identity())
        pk = PinnedKey.query.filter_by(user_id=user_id, username=data["username"]).first()
        if pk:
            pk.fingerprint = data["fingerprint"]
        else:
            pk = PinnedKey(user_id=user_id, username=data["username"], fingerprint=data["fingerprint"])

            db.session.add(pk)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return {"message": "Failed to store pinned key."}, 500
        return {"message": "Pinned key stored."}, 200

class AccountSettings(Resource):
    """Update the authenticated user's account information."""

    @jwt_required()
    def put(self):
        data = request.get_json() or {}
        user_id = int(get_jwt_identity())
        user = db.session.get(User, user_id)
        if not user:
            return {"message": "User not found"}, 404

        updated = False

        new_email = data.get("email")
        if new_email:
            if len(new_email) > 120 or '@' not in new_email:
                return {"message": "Invalid email address."}, 400
            user.email = new_email
            updated = True

        current_pw = data.get("currentPassword")
        new_pw = data.get("newPassword")
        if current_pw and new_pw:
            if len(new_pw) < 6:
                return {"message": "New password must be at least 6 characters."}, 400
            if check_password_hash(user.password_hash, current_pw):
                # Rehash the new password using PBKDF2 with SHA-256
                user.password_hash = generate_password_hash(new_pw, method="pbkdf2:sha256")
                updated = True
            else:
                return {"message": "Current password is incorrect."}, 400

        if not updated:
            return {"message": "No account changes provided."}, 400

        try:
            db.session.commit()
        except Exception:
            app.logger.exception("Failed to update account settings")
            db.session.rollback()
            return {"message": "Failed to update account."}, 500
        return {"message": "Account updated."}, 200


class RefreshToken(Resource):
    """Issue a new JWT for the authenticated user."""

    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        new_token = create_access_token(identity=str(user_id))
        return {"access_token": new_token}, 200


class RevokeToken(Resource):
    """Revoke the current JWT so it can no longer be used."""

    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        token_blocklist.add(jti)
        return {"message": "Token revoked"}, 200


class Groups(Resource):
    """Create and list groups for the authenticated user."""

    @jwt_required()
    def get(self):
        user_id = int(get_jwt_identity())
        groups = (
            Group.query.join(GroupMember)
            .filter(GroupMember.user_id == user_id)
            .all()
        )
        return {
            "groups": [
                {"id": g.id, "name": g.name, "owner_id": g.owner_id}
                for g in groups
            ]
        }

    @jwt_required()
    def post(self):
        data = request.get_json() or {}
        name = data.get("name")
        members = data.get("members", [])
        if not name or not isinstance(members, list):
            return {"message": "Name and member list required"}, 400
        user_id = int(get_jwt_identity())
        group = Group(name=name, owner_id=user_id)
        try:
            db.session.add(group)
            db.session.flush()
            db.session.add(GroupMember(group_id=group.id, user_id=user_id))
            for username in members:
                u = User.query.filter_by(username=username).first()
                if u:
                    db.session.add(GroupMember(group_id=group.id, user_id=u.id))
            db.session.commit()
        except Exception:
            db.session.rollback()
            return {"message": "Failed to create group."}, 500
        return {"group_id": group.id}, 201


class GroupMessages(Resource):
    """Retrieve or create messages for a group."""

    @jwt_required()
    def get(self, group_id):
        user_id = int(get_jwt_identity())
        member = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
        if not member:
            return {"message": "Not a member"}, 403
        messages = Message.query.filter_by(group_id=group_id).all()
        results = []
        for m in messages:
            nonce = b64decode(m.nonce)
            ciphertext = b64decode(m.content)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            results.append(
                {
                    "id": m.id,
                    "content": b64encode(plaintext).decode(),
                    "timestamp": m.timestamp.isoformat(),
                    "sender_id": m.sender_id,
                }
            )
        return {"messages": results}

    @jwt_required()
    def post(self, group_id):
        user_id = int(get_jwt_identity())
        member = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
        if not member:
            return {"message": "Not a member"}, 403
        data = group_message_parser.parse_args()
        try:
            client_ciphertext = b64decode(data["content"], validate=True)
        except Exception:
            return {"message": "Invalid base64 content."}, 400
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, client_ciphertext, None)
        new_message = Message(
            content=b64encode(ciphertext).decode(),
            nonce=b64encode(nonce).decode(),
            user_id=user_id,
            sender_id=user_id,
            recipient_id=0,
            group_id=group_id,
        )
        try:
            db.session.add(new_message)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return {"message": "Failed"}, 500
        # Broadcast to members
        members = GroupMember.query.filter_by(group_id=group_id).all()
        for mem in members:
            socketio.emit(
                "new_message",
                {"content": data["content"], "sender_id": user_id, "group_id": group_id},
                to=str(mem.user_id),
            )
        return {"message": "Sent"}, 201


class FilesResource(Resource):
    """Upload and download encrypted files."""

    @jwt_required()
    def post(self):
        user_id = int(get_jwt_identity())
        file = request.files.get("file")
        if not file:
            data = request.form
            filename = data.get("filename")
            content_b64 = data.get("content")
        else:
            filename = file.filename
            content_b64 = b64encode(file.read()).decode()
        if not filename or not content_b64:
            return {"message": "Missing file"}, 400
        try:
            client_bytes = b64decode(content_b64, validate=True)
        except Exception:
            return {"message": "Invalid base64"}, 400
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, client_bytes, None)
        f = File(
            filename=filename,
            content=ciphertext,
            nonce=b64encode(nonce).decode(),
            user_id=user_id,
        )
        try:
            db.session.add(f)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return {"message": "Failed"}, 500
        return {"file_id": f.id}, 201

    @jwt_required()
    def get(self, file_id):
        f = File.query.get(file_id)
        if not f:
            return {"message": "Not found"}, 404
        plaintext = aesgcm.decrypt(b64decode(f.nonce), f.content, None)
        return {
            "filename": f.filename,
            "content": b64encode(plaintext).decode(),
        }
