"""REST API resources for PrivateLine.

This module defines the Flask-RESTful resources used by the backend. Uploaded
files are limited to ``MAX_FILE_SIZE`` bytes and message pagination parameters
are validated for reasonable bounds. Messages may optionally include a
``delete_on_read`` flag indicating they should be purged as soon as the
recipient marks them read.

Recent changes introduce rate limiting on authentication endpoints and store the
original MIME type of uploaded files so downloads return the correct
``Content-Type`` header. Account management now validates that email addresses
remain unique when changed via the settings endpoint to prevent database
integrity errors. Passwords are hashed with Argon2 while still accepting legacy
PBKDF2 hashes for seamless upgrades.

2025 update: File uploads now inspect the request ``Content-Length`` and stream
data in chunks so oversized payloads are rejected before fully loading into
memory. This guards against memory exhaustion attacks and ensures we abort
uploads exceeding ``MAX_FILE_SIZE`` as early as possible.

2025 update: Base64 decoding for stored message ``nonce`` and ``content`` now
uses strict validation to detect corruption. Invalid records are skipped so a
single malformed entry cannot break message retrieval.

2025 update: Message creation now validates that any referenced ``file_id``
belongs to the sender or target group, rejecting mismatched or unauthorized
attachments before they are persisted.
2026 update: ``verify_password`` now guards against malformed legacy hashes by
catching both ``TypeError`` and ``ValueError`` from ``check_password_hash`` so
unexpected inputs simply cause authentication to fail rather than error.
2027 update: File uploads now record ``uploader_id`` and downloads permit
original uploaders to retrieve unreferenced files. ``validate_file_ownership``
uses this information to block unauthorized reuse of attachments.
"""

# 2024 update: Introduced Argon2 password hashing via ``PasswordHasher`` and
# added ``verify_password`` to support existing PBKDF2 accounts. All new
# registrations now store Argon2 hashes by default.

from flask_restful import Resource, reqparse, inputs
from flask import request, jsonify
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from base64 import b64encode, b64decode
import binascii
import os
from typing import Optional, Tuple
from .models import User, Message, PinnedKey, PushToken
from .models import Group, GroupMember, File, ConversationRetention
from .ratchet import get_ratchet
from .app import (
    db,
    app,
    socketio,
    token_blocklist,
    limiter,
    FILE_RETENTION_DAYS,
)
from sqlalchemy.exc import SQLAlchemyError
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
    set_access_cookies,
    unset_jwt_cookies,
)

# AES-GCM key for encrypting stored messages
_aes_key_env = os.environ.get("AES_KEY")
if not _aes_key_env:
    app.logger.error(
        "AES_KEY environment variable not set; cannot decrypt stored messages."
    )
    raise RuntimeError("AES_KEY environment variable is required for encryption")
AES_KEY = b64decode(_aes_key_env)
aesgcm = AESGCM(AES_KEY)

# Maximum allowed upload size in bytes. Defaults to 5 MB but can be overridden
# with the ``MAX_FILE_SIZE`` environment variable.
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 5 * 1024 * 1024))

# Argon2 password hasher used for new registrations. Legacy PBKDF2 hashes
# created by earlier versions remain supported through a compatibility
# check in :func:`verify_password`.
password_hasher = PasswordHasher()


def verify_password(stored_hash: str, candidate: str) -> bool:
    """Return ``True`` when ``candidate`` matches ``stored_hash``.

    The function first attempts verification using Argon2. If ``stored_hash``
    contains an unsupported format, the legacy PBKDF2 check from Werkzeug is
    used for backward compatibility. Any error encountered during either
    verification method results in ``False`` to prevent exception leakage.
    """

    try:
        return password_hasher.verify(stored_hash, candidate)
    except VerifyMismatchError:
        # The provided password is definitively incorrect
        return False
    except InvalidHash:
        # ``stored_hash`` is not a valid Argon2 digest; fall back to Werkzeug's
        # PBKDF2 helper used by older accounts.
        try:
            return check_password_hash(stored_hash, candidate)
        except (TypeError, ValueError):
            # Werkzeug raises ``TypeError`` when ``candidate`` is not a string
            # and ``ValueError`` for malformed hashes. In both cases we treat
            # the password as invalid instead of bubbling up the error.
            return False
        except Exception:
            # Defensive catch-all for any other unexpected issues during
            # legacy verification.
            return False
    except Exception:
        # Any other exception from Argon2 verification indicates failure.
        return False


# Request parser for messages
message_parser = reqparse.RequestParser()
message_parser.add_argument(
    "content", required=True, location="form", help="Content is required."
)
message_parser.add_argument("recipient", required=False, location="form")
message_parser.add_argument("group_id", required=False, location="form")
message_parser.add_argument("file_id", required=False, location="form")
message_parser.add_argument("signature", required=True, location="form")
message_parser.add_argument(
    "expires_at", required=False, location="form", help="ISO8601 expiration timestamp"
)
message_parser.add_argument(
    "delete_on_read",
    required=False,
    location="form",
    type=inputs.boolean,
)


def validate_file_ownership(
    sender_id: int, group_id: Optional[int], file_id: int
) -> Tuple[bool, dict, int]:
    """Ensure ``file_id`` exists and is tied to ``sender_id`` or ``group_id``.

    The server now records an ``uploader_id`` with each :class:`File`. Before a
    file is first attached to a message, only the original uploader may send it
    directly and group attachments require that the uploader belong to the
    target group. After a file has been referenced, reuse is limited to the
    original sender (for direct chats) or the same group. A tuple of
    ``(bool, dict, int)`` is returned where the boolean indicates success and
    the dict/int pair represent an error response when validation fails.
    """

    record = db.session.get(File, file_id)
    if not record:
        # Client supplied a non-existent ``file_id``
        return False, {"message": "Invalid file id."}, 400

    references = Message.query.filter_by(file_id=file_id).all()
    if not references:
        if group_id is not None:
            # Ensure the uploader is a member of the target group before the
            # first attachment occurs.
            member = GroupMember.query.filter_by(
                group_id=group_id, user_id=record.uploader_id
            ).first()
            if not member:
                return False, {"message": "Forbidden"}, 403
        else:
            # For direct messages only the uploader may send the file prior to
            # any message references.
            if record.uploader_id != sender_id:
                return False, {"message": "Forbidden"}, 403
        return True, {}, 200
    for msg in references:
        if group_id is not None:
            # Group attachments must only appear in the same group
            if msg.group_id != group_id:
                return False, {"message": "Forbidden"}, 403
        else:
            # Direct messages require the same sender and must not have been
            # attached to a group conversation previously
            if msg.sender_id != sender_id or msg.group_id is not None:
                return False, {"message": "Forbidden"}, 403

    return True, {}, 200

# --- Retention helpers ------------------------------------------------------

def conversation_retention_days(user_id: int, msg: Message) -> int:
    """Return the retention period in days for ``msg`` as seen by ``user_id``."""
    if msg.group_id is not None:
        grp = db.session.get(Group, msg.group_id)
        if grp and grp.retention_days:
            return grp.retention_days
    else:
        peer = msg.recipient_id if msg.sender_id == user_id else msg.sender_id
        custom = ConversationRetention.query.filter_by(
            owner_id=user_id, peer_id=peer
        ).first()
        if custom:
            return custom.retention_days
    user = db.session.get(User, user_id)
    return user.message_retention_days

# Token serializer (legacy).  JWT is now used instead of this custom mechanism.
# s = Serializer(app.config['SECRET_KEY'], expires_in=3600)

# The previous implementation relied on a custom token_required decorator that
# used itsdangerous for token verification.  The project now leverages
# Flask-JWT-Extended, so authentication decorators below use @jwt_required.


# --- Push Notification Helpers ---
def send_apns(token: str, message: str) -> None:
    """Send a push notification via APNs if credentials are configured."""
    try:
        from apns2.client import APNsClient
        from apns2.payload import Payload

        cert = os.environ.get("APNS_CERT")
        topic = os.environ.get("APNS_TOPIC")
        if not cert or not topic:
            return
        use_sandbox = os.environ.get("APNS_USE_SANDBOX", "true").lower() != "false"
        client = APNsClient(cert, use_sandbox=use_sandbox)
        payload = Payload(alert=message, sound="default", badge=1)
        client.send_notification(token, payload, topic=topic)
    except Exception as e:
        app.logger.warning("Failed to send APNs notification: %s", e)


def send_web_push(subscription_json: str, message: str) -> None:
    """Send a Web Push notification if VAPID keys are configured."""
    try:
        from pywebpush import webpush
        import json

        private_key = os.environ.get("VAPID_PRIVATE_KEY")
        if not private_key:
            return
        webpush(
            json.loads(subscription_json),
            data=message,
            vapid_private_key=private_key,
            vapid_claims={
                "sub": os.environ.get("VAPID_SUBJECT", "mailto:admin@example.com")
            },
        )
    except Exception as e:
        app.logger.warning("Failed to send web push: %s", e)


def send_fcm(token: str, message: str) -> None:
    """Send a push notification via Firebase Cloud Messaging."""
    try:
        import requests

        server_key = os.environ.get("FCM_SERVER_KEY")
        if not server_key:
            return
        headers = {
            "Authorization": f"key={server_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "to": token,
            "notification": {"title": "PrivateLine", "body": message},
        }
        requests.post(
            "https://fcm.googleapis.com/fcm/send",
            json=payload,
            headers=headers,
            timeout=5,
        )
    except Exception as e:
        app.logger.warning("Failed to send FCM notification: %s", e)


def send_push_notifications(user_id: int, message: str) -> None:
    """Send notifications to all registered tokens for the user."""
    tokens = PushToken.query.filter_by(user_id=user_id).all()
    # Each token represents a push subscription for a specific platform.
    for t in tokens:
        if t.platform == "web":
            send_web_push(t.token, message)
        elif t.platform == "android":
            send_fcm(t.token, message)
        else:
            send_apns(t.token, message)


"""
The private key is encrypted using AES-256 in GCM mode,
with a key derived from the user's password using PBKDF2.
The encrypted private key, salt, and nonce are then
sent to the user encoded in base64.
"""


class Register(Resource):
    """Create a new user and return the encrypted private key."""

    # Apply rate limiting to throttle repeated registration attempts.
    decorators = [limiter.limit("10/minute")]

    def post(self):
        """Handle POST requests for user registration."""
        # Accept both JSON and form-encoded input
        data = request.get_json(silent=True)
        if not data:
            data = request.form.to_dict()

        required = {"username", "email", "password"}
        if not data or not required <= data.keys():
            return {"message": "Username, email and password are required."}, 400

        if len(data["username"]) > 64 or len(data["email"]) > 120:
            return {"message": "Username or email too long."}, 400
        if "@" not in data["email"]:
            return {"message": "Invalid email address."}, 400

        # Check if the username is already taken
        user = User.query.filter_by(username=data["username"]).first()
        if user:
            return {"message": "A user with that username already exists."}, 400

        # Check if the email is already registered
        user = User.query.filter_by(email=data["email"]).first()
        if user:
            return {"message": "A user with that email already exists."}, 400

        if len(data["password"]) < 6:
            return {"message": "Password must be at least 6 characters."}, 400

        # Hash the password using Argon2 for modern, memory-hard protection.
        # ``PasswordHasher`` automatically generates a random salt and encodes
        # all parameters within the returned string.
        hashed_password = password_hasher.hash(data["password"])

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
        password = data["password"].encode()  # Encode the user's password as bytes
        salt = os.urandom(16)  # Generate a random salt (16 bytes)

        # Key Derivation Function (KDF) to derive a cryptographic key from the password using PBKDF2 with HMAC and SHA-256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  # Use SHA-256 hash algorithm
            length=32,  # Length of derived key (32 bytes)
            salt=salt,  # Salt for the KDF
            iterations=200000,  # Number of iterations for the KDF
            backend=default_backend(),  # Cryptographic backend
        )
        key = kdf.derive(password)  # Derive the key using the user's password

        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        aes = AESGCM(key)

        private_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )

        encrypted_private_key = aes.encrypt(nonce, private_bytes, None)

        # Create a new user and add it to the database
        new_user = User(
            username=data["username"],
            email=data["email"],
            password_hash=hashed_password,
            public_key_pem=public_key_pem,
        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except SQLAlchemyError:
            app.logger.exception("Failed to register user")
            db.session.rollback()
            return {"message": "Registration failed."}, 500

        # Send encrypted private key and encryption details to the user
        return {
            "message": "User registered successfully.",  # Confirmation message
            "encrypted_private_key": b64encode(
                encrypted_private_key
            ).decode(),  # Base64-encoded encrypted private key
            "salt": b64encode(salt).decode(),  # Base64-encoded salt
            "nonce": b64encode(nonce).decode(),  # Base64-encoded nonce
            "fingerprint": fingerprint,
        }, 201


class Login(Resource):
    """Authenticate a user and return a JWT access token."""

    # Limit the frequency of login attempts to mitigate brute-force attacks.
    decorators = [limiter.limit("10/minute")]

    def post(self):
        """Authenticate credentials and issue an access token."""
        data = request.get_json() or {}

        if "username" not in data or "password" not in data:
            return {"message": "Username and password are required."}, 400

        # Query the database for the user with the given username
        user = User.query.filter_by(username=data["username"]).first()

        if user and verify_password(user.password_hash, data["password"]):
            access_token = create_access_token(identity=str(user.id))
            resp = jsonify({"access_token": access_token})
            set_access_cookies(resp, access_token)
            return resp
        return {"message": "Invalid username or password"}, 401


class PublicKey(Resource):
    """Return the public key for the given username."""

    @jwt_required()
    def get(self, username):
        """Fetch the PEM encoded public key for ``username``."""
        user = User.query.filter_by(username=username).first()
        if not user:
            return {"message": "User not found"}, 404
        return {"public_key": user.public_key_pem}


class Users(Resource):
    """Return a list of usernames, optionally filtered by a search query."""

    @jwt_required()
    def get(self):
        q = request.args.get("q")
        query = User.query
        if q:
            query = query.filter(User.username.contains(q))
        users = [u.username for u in query.all()]
        return {"users": users}


class Groups(Resource):
    """Create or list chat groups."""

    @jwt_required()
    def get(self):
        """Return all available groups."""
        groups = Group.query.all()
        return {"groups": [{"id": g.id, "name": g.name} for g in groups]}

    @jwt_required()
    def post(self):
        """Create a new group owned by the requester."""
        data = request.get_json() or {}
        name = data.get("name")
        if not name:
            return {"message": "Group name required"}, 400
        if Group.query.filter_by(name=name).first():
            return {"message": "Group exists"}, 400
        g = Group(name=name)
        db.session.add(g)
        db.session.commit()
        # Add creator as member
        uid = int(get_jwt_identity())
        gm = GroupMember(group_id=g.id, user_id=uid)
        db.session.add(gm)
        db.session.commit()
        return {"id": g.id, "name": g.name}, 201


class GroupMembers(Resource):
    """Manage membership of a group."""

    @jwt_required()
    def post(self, group_id):
        """Join ``group_id`` or invite another user by username or id."""
        uid = int(get_jwt_identity())
        g = db.session.get(Group, group_id)
        if not g:
            return {"message": "Not found"}, 404

        data = request.get_json() or {}

        target_id = uid
        if "username" in data:
            user = User.query.filter_by(username=data["username"]).first()
            if not user:
                return {"message": "User not found"}, 404
            target_id = user.id
        elif "user_id" in data:
            user = db.session.get(User, data["user_id"])
            if not user:
                return {"message": "User not found"}, 404
            target_id = user.id

        if (
            target_id != uid
            and not GroupMember.query.filter_by(group_id=group_id, user_id=uid).first()
        ):
            return {"message": "Not a member"}, 403

        if GroupMember.query.filter_by(group_id=group_id, user_id=target_id).first():
            return {"message": "Already a member"}, 400

        gm = GroupMember(group_id=group_id, user_id=target_id)
        db.session.add(gm)
        db.session.commit()
        return {"message": "added"}, 201


class GroupMemberResource(Resource):
    """Handle operations on a single group member."""

    @jwt_required()
    def delete(self, group_id, user_id):
        """Remove ``user_id`` from ``group_id`` or allow the user to leave."""
        current = int(get_jwt_identity())
        g = db.session.get(Group, group_id)
        if not g:
            return {"message": "Not found"}, 404

        gm = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
        if not gm:
            return {"message": "Not found"}, 404

        if (
            current != user_id
            and not GroupMember.query.filter_by(
                group_id=group_id, user_id=current
            ).first()
        ):
            return {"message": "Not a member"}, 403

        db.session.delete(gm)
        db.session.commit()
        return {"message": "removed"}, 200


class GroupKey(Resource):
    """Return or rotate the AES key for a group."""

    @jwt_required()
    def get(self, group_id):
        """Return the current base64-encoded AES key for ``group_id``."""
        uid = int(get_jwt_identity())
        if not GroupMember.query.filter_by(group_id=group_id, user_id=uid).first():
            return {"message": "Not a member"}, 403
        g = db.session.get(Group, group_id)
        if not g:
            return {"message": "Not found"}, 404
        return {"key": g.aes_key}

    @jwt_required()
    def put(self, group_id):
        """Rotate and return a new AES key for ``group_id``."""
        uid = int(get_jwt_identity())
        if not GroupMember.query.filter_by(group_id=group_id, user_id=uid).first():
            return {"message": "Not a member"}, 403
        g = db.session.get(Group, group_id)
        if not g:
            return {"message": "Not found"}, 404
        g.aes_key = b64encode(os.urandom(32)).decode()
        db.session.commit()
        return {"key": g.aes_key}


class GroupRetention(Resource):
    """Configure message retention for a group."""

    @jwt_required()
    def put(self, group_id):
        """Set ``retention_days`` for the specified group."""
        uid = int(get_jwt_identity())
        if not GroupMember.query.filter_by(group_id=group_id, user_id=uid).first():
            return {"message": "Not a member"}, 403
        g = db.session.get(Group, group_id)
        if not g:
            return {"message": "Not found"}, 404
        data = request.get_json() or {}
        days = data.get("retention_days")
        try:
            days = int(days)
        except (TypeError, ValueError):
            return {"message": "Invalid retention"}, 400
        if days < 1 or days > 365:
            return {"message": "Retention must be between 1 and 365"}, 400
        g.retention_days = days
        db.session.commit()
        return {"message": "updated"}, 200


class GroupMessages(Resource):
    """Send or retrieve messages for a group with additional server-side secrecy.

    Client payloads are still encrypted end-to-end using the shared group key.
    Before persistence the server applies :class:`DoubleRatchet` encryption so
    that every stored message is protected with a unique key. Reading a message
    rotates the ratchet's root key which prevents the same ciphertext from being
    decrypted again, providing forward secrecy for data at rest.
    """

    @jwt_required()
    def get(self, group_id):
        """Return all messages for ``group_id`` decrypted with the server key."""
        uid = int(get_jwt_identity())
        if not GroupMember.query.filter_by(group_id=group_id, user_id=uid).first():
            return {"message": "Not a member"}, 403
        limit = request.args.get("limit", default=50, type=int)
        offset = request.args.get("offset", default=0, type=int)
        if limit < 1 or limit > 100 or offset < 0:
            return {"message": "invalid pagination"}, 400
        all_msgs = (
            Message.query.filter_by(group_id=group_id)
            .filter(
                (Message.expires_at.is_(None))
                | (Message.expires_at > datetime.utcnow())
            )
            .order_by(Message.timestamp.asc())
            .all()
        )
        slice_start = max(len(all_msgs) - offset - limit, 0)
        slice_end = len(all_msgs) - offset
        result = []
        for idx, msg in enumerate(all_msgs):
            # Decode the base64-encoded nonce and ciphertext. ``validate=True``
            # causes ``b64decode`` to raise ``binascii.Error`` if the stored
            # value contains non-base64 characters, allowing us to detect
            # database corruption. Corrupted records are skipped so that a
            # single bad message does not break retrieval for the entire group.
            try:
                nonce = b64decode(msg.nonce, validate=True)
                ciphertext = b64decode(msg.content, validate=True)
            except binascii.Error:
                app.logger.warning(
                    "Skipping message %s with invalid base64 content", msg.id
                )
                continue
            # Each group is treated as a unique conversation for the ratchet.
            ratchet = get_ratchet(str(msg.sender_id), f"group:{group_id}")
            plaintext_bytes = ratchet.decrypt(ciphertext, nonce)
            plaintext_b64 = b64encode(plaintext_bytes).decode()
            try:
                user = db.session.get(User, msg.sender_id)
                user.public_key.verify(
                    b64decode(msg.signature),
                    plaintext_b64.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            except InvalidSignature:
                continue
            days = conversation_retention_days(uid, msg)
            if msg.read and msg.timestamp <= datetime.utcnow() - timedelta(days=days):
                continue
            if slice_start <= idx < slice_end:
                result.append(
                    {
                        "id": msg.id,
                        "content": plaintext_b64,
                        "timestamp": msg.timestamp.isoformat(),
                        "sender_id": msg.sender_id,
                        "file_id": msg.file_id,
                        "read": msg.read,
                        "expires_at": (
                            msg.expires_at.isoformat() if msg.expires_at else None
                        ),
                    }
                )
        # ``msgs`` was ordered ascending for ratchet purposes; reverse here so
        # clients see newest messages first.
        return {"messages": list(reversed(result))}

    @jwt_required()
    def post(self, group_id):
        """Store an encrypted group message and notify members."""
        uid = int(get_jwt_identity())
        if not GroupMember.query.filter_by(group_id=group_id, user_id=uid).first():
            return {"message": "Not a member"}, 403
        # Use the RequestParser above to validate the incoming form fields
        data = message_parser.parse_args()
        if len(data["content"]) > 2000:
            return {"message": "Message too long."}, 400
        try:
            client_ciphertext = b64decode(data["content"], validate=True)
        except (binascii.Error, ValueError):
            return {"message": "Invalid base64 content."}, 400
        try:
            sig = b64decode(data["signature"], validate=True)
        except (binascii.Error, ValueError):
            return {"message": "Invalid signature."}, 400
        user = db.session.get(User, uid)
        try:
            user.public_key.verify(
                sig,
                data["content"].encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return {"message": "Signature verification failed."}, 400

        # Validate file ownership when a ``file_id`` is supplied. A mismatched
        # or nonexistent file results in an error response before any
        # encryption work takes place.
        file_id_raw = data.get("file_id")
        if file_id_raw is not None:
            try:
                file_id = int(file_id_raw)
            except ValueError:
                return {"message": "Invalid file id."}, 400
            ok, err, code = validate_file_ownership(uid, group_id, file_id)
            if not ok:
                return err, code
        else:
            file_id = None
        # Apply the server-side double ratchet so the stored ciphertext is
        # protected even if the database is compromised. Each message uses a
        # unique key derived from the conversation state.
        ratchet = get_ratchet(str(uid), f"group:{group_id}")
        ciphertext, nonce = ratchet.encrypt(client_ciphertext)
        m = Message(
            content=b64encode(ciphertext).decode(),
            nonce=b64encode(nonce).decode(),
            user_id=uid,
            sender_id=uid,
            group_id=group_id,
            file_id=file_id,
            signature=data["signature"],
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            delete_on_read=data.get("delete_on_read") or False,
        )
        db.session.add(m)
        db.session.commit()
        socketio.emit(
            "new_message",
            {
                "id": m.id,
                "content": data["content"],
                "group_id": group_id,
                "file_id": file_id,
            },
            to=str(group_id),
        )
        return {"message": "sent", "id": m.id}, 201


class FileUpload(Resource):
    """Upload an encrypted file and return its id."""

    @jwt_required()
    def post(self):
        """Persist an uploaded file encrypted with AES-GCM.

        The implementation validates the request's ``Content-Length`` header and
        streams the file in manageable chunks. This prevents a client from
        exhausting server memory by advertising a small upload while streaming
        unbounded data. Chunks are concatenated only after confirming the total
        size does not exceed ``MAX_FILE_SIZE``.
        """

        # Ensure a file part was provided before performing any expensive work.
        if "file" not in request.files:
            return {"message": "file required"}, 400

        # Reject early when the client announces a body larger than allowed.
        if request.content_length and request.content_length > MAX_FILE_SIZE:
            return {"message": "file too large"}, 413

        f = request.files["file"]
        uid = int(get_jwt_identity())

        # Read the stream incrementally so uploads exceeding the limit are
        # detected without buffering the entire payload in memory.
        data_chunks = []
        total = 0
        for chunk in iter(lambda: f.stream.read(4096), b""):
            total += len(chunk)
            if total > MAX_FILE_SIZE:
                return {"message": "file too large"}, 413
            data_chunks.append(chunk)
        data = b"".join(data_chunks)

        sanitized = secure_filename(f.filename)
        nonce = os.urandom(12)
        # Encrypt the raw bytes using the server's symmetric key before writing
        # to the database so that file contents remain confidential at rest.
        ciphertext = aesgcm.encrypt(nonce, data, None)
        stored = nonce + ciphertext
        file_rec = File(
            filename=sanitized,
            mimetype=f.mimetype or "application/octet-stream",
            data=stored,
            # Use the global default retention unless changed later via a
            # database migration or explicit update.
            file_retention_days=FILE_RETENTION_DAYS,
            # Associate the upload with the current user so later requests can
            # verify ownership even before the file is attached to a message.
            uploader_id=uid,
        )
        db.session.add(file_rec)
        db.session.commit()
        return {"file_id": file_rec.id}, 201


class FileDownload(Resource):
    """Return a file by id."""

    @jwt_required()
    def get(self, file_id):
        """Decrypt and return the file if the requester is authorized."""
        uid = int(get_jwt_identity())
        f = db.session.get(File, file_id)
        if not f:
            return {"message": "Not found"}, 404
        # Verify the requester either uploaded the file or is associated with a
        # message that references it. This allows the original uploader to
        # retrieve the file even before it is attached to any message.
        authorized = f.uploader_id == uid
        if not authorized:
            msgs = Message.query.filter_by(file_id=file_id).all()
            for msg in msgs:
                if msg.group_id:
                    if GroupMember.query.filter_by(
                        group_id=msg.group_id, user_id=uid
                    ).first():
                        authorized = True
                        break
                elif msg.sender_id == uid or msg.recipient_id == uid:
                    authorized = True
                    break

        if not authorized:
            return {"message": "Forbidden"}, 403
        nonce = f.data[:12]
        ciphertext = f.data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        from flask import make_response

        resp = make_response(plaintext)
        # Restore the original content type so clients can infer the file type.
        resp.headers.set("Content-Type", f.mimetype)
        fname = secure_filename(f.filename)
        resp.headers.set("Content-Disposition", f"attachment; filename={fname}")
        # Increment the download counter and determine if the file has reached
        # its allowed number of downloads. ``max_downloads`` defaults to one so
        # attachments are removed after the first successful retrieval unless
        # explicitly overridden.
        f.download_count += 1
        reached_limit = f.download_count >= f.max_downloads
        if reached_limit:
            # Detach all messages referencing this file to avoid dangling
            # foreign key references before deleting the record.
            Message.query.filter_by(file_id=file_id).update({"file_id": None})
            db.session.delete(f)
        db.session.commit()
        if reached_limit:
            # Clean up any orphaned file records left from other operations.
            remove_orphan_files()
        return resp


def remove_orphan_files() -> None:
    """Delete uploaded files that are not referenced by any message."""

    from sqlalchemy import exists

    orphans = File.query.filter(~exists().where(Message.file_id == File.id)).all()
    if not orphans:
        return
    for record in orphans:
        db.session.delete(record)
    db.session.commit()


class Messages(Resource):
    """Retrieve or create encrypted chat messages.

    A lightweight double ratchet is used to encrypt the already encrypted
    client payload before it is stored in the database. Each decrypt operation
    advances the ratchet which means old ciphertext cannot be decrypted again
    with a previous state. This ensures forward secrecy for the server-side
    encryption layer.
    """

    decorators = [limiter.limit("50/minute")]
    # Apply per-user rate limiting to prevent abuse of the messaging endpoint.

    # Retrieve all messages. Requires a valid JWT token.
    @jwt_required()
    def get(self):
        """Return base64-encoded ciphertext for the authenticated user."""
        from sqlalchemy import or_

        current_user_id = int(get_jwt_identity())
        limit = request.args.get("limit", default=50, type=int)
        offset = request.args.get("offset", default=0, type=int)
        if limit < 1 or limit > 100 or offset < 0:
            return {"message": "invalid pagination"}, 400
        # Fetch all relevant messages in chronological order so the ratchet can
        # decrypt them sequentially. Pagination is applied after decryption to
        # keep the API stable while maintaining correct ratchet state.
        all_msgs = (
            Message.query.filter(
                or_(
                    Message.sender_id == current_user_id,
                    Message.recipient_id == current_user_id,
                )
            )
            .filter(
                (Message.expires_at.is_(None))
                | (Message.expires_at > datetime.utcnow())
            )
            .order_by(Message.timestamp.asc())
            .all()
        )
        slice_start = max(len(all_msgs) - offset - limit, 0)
        slice_end = len(all_msgs) - offset
        message_list = []
        for idx, msg in enumerate(all_msgs):
            # Strictly decode nonce and ciphertext. Invalid base64 indicates
            # tampering or data corruption. Such messages are skipped so that
            # clients still receive any remaining valid entries.
            try:
                nonce = b64decode(msg.nonce, validate=True)
                ciphertext = b64decode(msg.content, validate=True)
            except binascii.Error:
                app.logger.warning(
                    "Skipping message %s with invalid base64 content", msg.id
                )
                continue
            recipient_ref = (
                f"group:{msg.group_id}"
                if msg.group_id is not None
                else str(msg.recipient_id)
            )
            ratchet = get_ratchet(str(msg.sender_id), recipient_ref)
            plaintext_bytes = ratchet.decrypt(ciphertext, nonce)
            plaintext_b64 = b64encode(plaintext_bytes).decode()
            try:
                user = db.session.get(User, msg.sender_id)
                user.public_key.verify(
                    b64decode(msg.signature),
                    plaintext_b64.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            except InvalidSignature:
                continue
            days = conversation_retention_days(current_user_id, msg)
            if msg.read and msg.timestamp <= datetime.utcnow() - timedelta(days=days):
                continue
            if slice_start <= idx < slice_end:
                message_list.append(
                    {
                        "id": msg.id,
                        "content": plaintext_b64,
                        "timestamp": msg.timestamp.isoformat(),
                        "sender_id": msg.sender_id,
                        "recipient_id": msg.recipient_id,
                        "file_id": msg.file_id,
                        "read": msg.read,
                        "expires_at": (
                            msg.expires_at.isoformat() if msg.expires_at else None
                        ),
                    }
                )
        return {"messages": list(reversed(message_list))}

    # Send a new message. Rate limited via the class-level ``decorators``.
    @jwt_required()
    def post(self):
        """Store an encrypted message and broadcast it to clients."""
        data = message_parser.parse_args()
        uid = int(get_jwt_identity())

        # Arbitrary limit on encrypted payload size to prevent abuse
        if len(data["content"]) > 2000:
            return {"message": "Message too long."}, 400

        recipient = None
        gid = data.get("group_id")
        if data.get("recipient"):
            recipient = User.query.filter_by(username=data["recipient"]).first()
            if not recipient:
                return {"message": "Recipient not found."}, 404
        elif gid is None:
            return {"message": "Recipient or group_id required."}, 400
        else:
            # Verify the sender is a member of the target group
            if not GroupMember.query.filter_by(group_id=gid, user_id=uid).first():
                return {"message": "Not a member"}, 403

        # The client sends base64 encoded ciphertext. Decode it before applying
        # server-side encryption for storage.
        try:
            client_ciphertext = b64decode(data["content"], validate=True)
        except (binascii.Error, ValueError):
            return {"message": "Invalid base64 content."}, 400
        try:
            sig = b64decode(data["signature"], validate=True)
        except (binascii.Error, ValueError):
            return {"message": "Invalid signature."}, 400

        sender = db.session.get(User, uid)
        try:
            sender.public_key.verify(
                sig,
                data["content"].encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return {"message": "Signature verification failed."}, 400

        # Confirm referenced file exists and belongs to the sender or group.
        # This guards against attaching arbitrary ``file_id`` values.
        file_id_raw = data.get("file_id")
        if file_id_raw is not None:
            try:
                file_id = int(file_id_raw)
            except ValueError:
                return {"message": "Invalid file id."}, 400
            ok, err, code = validate_file_ownership(uid, gid, file_id)
            if not ok:
                return err, code
        else:
            file_id = None

        # Encrypt the user-supplied ciphertext using the double ratchet tied to
        # this sender/recipient pair (or group). The ratchet's encrypt method
        # returns both the ciphertext and nonce needed for decryption.
        recipient_ref = f"group:{gid}" if gid is not None else str(recipient.id)
        ratchet = get_ratchet(str(uid), recipient_ref)
        ciphertext, nonce = ratchet.encrypt(client_ciphertext)
        encrypted_content = b64encode(ciphertext).decode()
        nonce_b64 = b64encode(nonce).decode()

        current_user_id = uid
        new_message = Message(
            content=encrypted_content,
            nonce=nonce_b64,
            user_id=current_user_id,
            sender_id=current_user_id,
            recipient_id=recipient.id if recipient else None,
            group_id=gid,
            file_id=file_id,
            signature=data["signature"],
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            delete_on_read=data.get("delete_on_read") or False,
        )
        try:
            db.session.add(new_message)
            db.session.commit()
        except SQLAlchemyError:
            app.logger.exception("Failed to store message")
            db.session.rollback()
            return {"message": "Failed to store message."}, 500

        # Broadcast the encrypted message to connected clients via WebSockets
        if recipient:
            socketio.emit(
                "new_message",
                {
                    "id": new_message.id,
                    "content": data["content"],
                    "sender_id": current_user_id,
                    "recipient_id": recipient.id,
                    "file_id": file_id,
                },
                to=str(recipient.id),
            )
            send_push_notifications(recipient.id, "New message")
        else:
            socketio.emit(
                "new_message",
                {
                    "id": new_message.id,
                    "content": data["content"],
                    "sender_id": current_user_id,
                    "group_id": gid,
                    "file_id": file_id,
                },
                to=str(gid),
            )
            members = GroupMember.query.filter_by(group_id=gid).all()
            for m in members:
                if m.user_id != current_user_id:
                    send_push_notifications(m.user_id, "New group message")

        return {"message": "Message sent successfully.", "id": new_message.id}, 201


class MessageResource(Resource):
    """Delete or modify a single message."""

    @jwt_required()
    def delete(self, message_id):
        """Remove a message authored by the current user."""
        uid = int(get_jwt_identity())
        msg = db.session.get(Message, message_id)
        if not msg:
            return {"message": "Not found"}, 404
        if msg.sender_id != uid:
            return {"message": "Forbidden"}, 403
        db.session.delete(msg)
        db.session.commit()
        remove_orphan_files()
        return {"message": "deleted"}, 200


class MessageRead(Resource):
    """Mark a message as read by the recipient."""

    @jwt_required()
    def post(self, message_id):
        """Mark the specified message as read if the user is allowed."""
        uid = int(get_jwt_identity())
        msg = db.session.get(Message, message_id)
        if not msg:
            return {"message": "Not found"}, 404
        if msg.group_id is not None:
            if not GroupMember.query.filter_by(
                group_id=msg.group_id, user_id=uid
            ).first():
                return {"message": "Forbidden"}, 403
        elif msg.recipient_id != uid:
            return {"message": "Forbidden"}, 403
        msg.read = True
        if msg.delete_on_read:
            db.session.delete(msg)
            db.session.commit()
            remove_orphan_files()
        else:
            db.session.commit()
        return {"message": "read"}, 200


class UnreadCount(Resource):
    """Return the total number of unread messages for the authenticated user."""

    @jwt_required()
    def get(self):
        """Calculate unread counts for direct and group conversations.

        The method filters messages that:
        - Are addressed to the current user or a group they belong to.
        - Have not been marked as ``read``.
        - Have not expired yet.

        Returns
        -------
        dict
            ``{"unread": <int>}`` with the total message count.
        """

        uid = int(get_jwt_identity())
        now = datetime.utcnow()

        # Base query filtering unread and non-expired messages.
        base = Message.query.filter(
            Message.read.is_(False),
            (Message.expires_at.is_(None)) | (Message.expires_at > now),
        )

        # Direct messages addressed specifically to ``uid``.
        direct = base.filter(Message.recipient_id == uid).count()

        # Unread messages in groups ``uid`` participates in.
        group_ids = [gm.group_id for gm in GroupMember.query.filter_by(user_id=uid)]
        group_unread = (
            base.filter(Message.group_id.in_(group_ids)).count() if group_ids else 0
        )

        return {"unread": direct + group_unread}


class PinnedKeys(Resource):
    """Manage pinned key fingerprints for the authenticated user."""

    @jwt_required()
    def get(self):
        """Return all pinned key fingerprints for the current user."""
        user_id = int(get_jwt_identity())
        keys = PinnedKey.query.filter_by(user_id=user_id).all()
        return {
            "pinned_keys": [
                {"username": k.username, "fingerprint": k.fingerprint} for k in keys
            ]
        }

    @jwt_required()
    def post(self):
        """Create or update a pinned key fingerprint."""
        data = request.get_json(silent=True) or request.form.to_dict()
        if not data or "username" not in data or "fingerprint" not in data:
            return {"message": "Username and fingerprint are required."}, 400
        user_id = int(get_jwt_identity())
        pk = PinnedKey.query.filter_by(
            user_id=user_id, username=data["username"]
        ).first()
        if pk:
            pk.fingerprint = data["fingerprint"]
        else:
            pk = PinnedKey(
                user_id=user_id,
                username=data["username"],
                fingerprint=data["fingerprint"],
            )

            db.session.add(pk)
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            return {"message": "Failed to store pinned key."}, 500
        return {"message": "Pinned key stored."}, 200


class ConversationRetentionResource(Resource):
    """Set retention for a direct conversation."""

    @jwt_required()
    def put(self, username):
        """Store ``retention_days`` for the conversation with ``username``."""
        owner_id = int(get_jwt_identity())
        peer = User.query.filter_by(username=username).first()
        if not peer:
            return {"message": "User not found"}, 404
        data = request.get_json() or {}
        days = data.get("retention_days")
        try:
            days = int(days)
        except (TypeError, ValueError):
            return {"message": "Invalid retention"}, 400
        if days < 1 or days > 365:
            return {"message": "Retention must be between 1 and 365"}, 400
        rec = ConversationRetention.query.filter_by(owner_id=owner_id, peer_id=peer.id).first()
        if rec:
            rec.retention_days = days
        else:
            rec = ConversationRetention(owner_id=owner_id, peer_id=peer.id, retention_days=days)
            db.session.add(rec)
        db.session.commit()
        return {"message": "updated"}, 200


class PushTokenResource(Resource):
    """Store push notification tokens for the authenticated user."""

    @jwt_required()
    def post(self):
        """Save a Web or APNs token so push notifications can be sent."""
        data = request.get_json() or {}
        token = data.get("token")
        if not token:
            return {"message": "Token is required."}, 400

        platform = data.get("platform", "ios")
        user_id = int(get_jwt_identity())
        enc = PushToken.encrypt_value(token)
        pt = PushToken.query.filter_by(user_id=user_id, token=enc).first()
        if pt:
            pt.platform = platform
        else:
            pt = PushToken(user_id=user_id, token=token, platform=platform)
            db.session.add(pt)
        try:
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            return {"message": "Failed to store token."}, 500
        return {"message": "Token stored."}, 200

    @jwt_required()
    def delete(self):
        """Remove a push token for the current user."""
        data = request.get_json() or {}
        token = data.get("token")
        if not token:
            return {"message": "Token is required."}, 400

        user_id = int(get_jwt_identity())
        enc = PushToken.encrypt_value(token)
        pt = PushToken.query.filter_by(user_id=user_id, token=enc).first()
        if pt:
            db.session.delete(pt)
            try:
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()
                return {"message": "Failed to delete token."}, 500
        return {"message": "Token deleted."}, 200


class AccountSettings(Resource):
    """Update the authenticated user's account information."""

    @jwt_required()
    def put(self):
        """Change email or password for the logged in user."""
        data = request.get_json() or {}
        user_id = int(get_jwt_identity())
        user = db.session.get(User, user_id)
        if not user:
            return {"message": "User not found"}, 404

        updated = False

        new_email = data.get("email")
        if new_email:
            if len(new_email) > 120 or "@" not in new_email:
                return {"message": "Invalid email address."}, 400
            # Prevent changing to an email address that already belongs to
            # another account. Without this check the unique constraint on the
            # ``email`` column would raise an error during commit and result in
            # a 500 response.
            existing = User.query.filter_by(email=new_email).first()
            if existing and existing.id != user_id:
                return {"message": "Email already registered."}, 400
            if new_email != user.email:
                user.email = new_email
                updated = True

        current_pw = data.get("currentPassword")
        new_pw = data.get("newPassword")
        if current_pw and new_pw:
            if len(new_pw) < 6:
                return {"message": "New password must be at least 6 characters."}, 400
            if verify_password(user.password_hash, current_pw):
                # Replace the stored hash with a new Argon2-derived value.
                user.password_hash = password_hasher.hash(new_pw)
                updated = True
            else:
                return {"message": "Current password is incorrect."}, 400

        # Optional per-user retention policy controlling when read messages are
        # purged. Values outside the 1-365 day range are rejected.
        retention = data.get("messageRetentionDays")
        if retention is not None:
            try:
                days = int(retention)
            except (TypeError, ValueError):
                return {"message": "Invalid retention value."}, 400
            if days < 1 or days > 365:
                return {"message": "Retention must be between 1 and 365 days."}, 400
            if days != user.message_retention_days:
                user.message_retention_days = days
                updated = True

        if not updated:
            return {"message": "No account changes provided."}, 400

        try:
            db.session.commit()
        except SQLAlchemyError:
            app.logger.exception("Failed to update account settings")
            db.session.rollback()
            return {"message": "Failed to update account."}, 500
        return {"message": "Account updated."}, 200


class RefreshToken(Resource):
    """Issue a new JWT for the authenticated user."""

    @jwt_required()
    def post(self):
        """Return a freshly minted token for the current user."""
        user_id = get_jwt_identity()
        new_token = create_access_token(identity=str(user_id))
        resp = jsonify({"access_token": new_token})
        set_access_cookies(resp, new_token)
        return resp


class RevokeToken(Resource):
    """Revoke the current JWT so it can no longer be used."""

    @jwt_required()
    def post(self):
        """Invalidate the calling JWT by adding its jti to the blocklist."""
        jti = get_jwt()["jti"]
        token_blocklist.add(jti)
        resp = jsonify({"message": "Token revoked"})
        unset_jwt_cookies(resp)
        return resp


class DeleteAccount(Resource):
    """Remove the authenticated user's account and revoke the token."""

    @jwt_required()
    def delete(self):
        """Delete the user and all related records from the database."""
        from sqlalchemy import or_

        user_id = int(get_jwt_identity())
        user = db.session.get(User, user_id)
        if not user:
            return {"message": "User not found"}, 404

        try:
            # Remove chat messages where the user appears in any role
            Message.query.filter(
                or_(
                    Message.user_id == user_id,
                    Message.sender_id == user_id,
                    Message.recipient_id == user_id,
                )
            ).delete(synchronize_session=False)

            # Remove group memberships and push tokens belonging to the user
            GroupMember.query.filter_by(user_id=user_id).delete()
            PushToken.query.filter_by(user_id=user_id).delete()

            # Remove pinned key records owned by the user
            PinnedKey.query.filter_by(user_id=user_id).delete()

            # Finally delete the user record itself
            db.session.delete(user)
            db.session.commit()
            remove_orphan_files()
        except SQLAlchemyError:
            db.session.rollback()
            return {"message": "Failed to delete account."}, 500

        # Revoke the JWT that initiated the request so it cannot be reused
        jti = get_jwt()["jti"]
        token_blocklist.add(jti)
        resp = jsonify({"message": "Account deleted"})
        unset_jwt_cookies(resp)
        return resp
