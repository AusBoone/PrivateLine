"""SQLAlchemy models for PrivateLine.

This module defines the database schema used by the Flask backend. A recent
update introduces a ``created_at`` timestamp on :class:`PushToken` so the
backend can expire stale tokens. Expired messages and push tokens are purged
periodically by scheduled jobs in ``app.py``.
"""

from .app import db
from datetime import datetime
from sqlalchemy.ext.hybrid import hybrid_property
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import os


class User(db.Model):
    """Database representation of an application user.

    When a new user registers, a public/private RSA key pair is generated. The
    public key is stored in this model and the encrypted private key is returned
    to the client for safekeeping (see the :class:`Register` resource for
    details).
    """

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False)
    # Number of days to retain read messages before deletion. Defaults to 30 to
    # keep recent history while limiting stored personal data.
    message_retention_days = db.Column(
        db.Integer, nullable=False, server_default="30"
    )

    @hybrid_property
    def public_key(self):
        return serialization.load_pem_public_key(
            self.public_key_pem.encode(), default_backend()
        )

    @staticmethod
    def generate_key_pair():
        """Return a new RSA private key and the corresponding public key PEM."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return private_key, public_key_pem


class Group(db.Model):
    """A chat group used for group messaging."""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    # Base64 encoded 256-bit AES key used to encrypt messages for this group.
    aes_key = db.Column(
        db.String(44),
        nullable=False,
        default=lambda: b64encode(os.urandom(32)).decode(),
    )


class GroupMember(db.Model):
    """Association table linking users to groups."""

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class File(db.Model):
    """Binary file uploaded by a user and stored encrypted.

    The ``mimetype`` column records the original ``Content-Type`` sent by the
    client so downloads can restore the appropriate header. ``data`` holds the
    AES-GCM nonce followed by the ciphertext produced when encrypting the
    uploaded bytes.
    """

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    # MIME type supplied by the client, e.g. ``text/plain`` or
    # ``application/pdf``.  Stored to preserve the original type on download.
    mimetype = db.Column(
        db.String(128), nullable=False, default="application/octet-stream"
    )
    # ``data`` stores nonce + ciphertext produced by AES-GCM
    data = db.Column(db.LargeBinary, nullable=False)


class Message(db.Model):
    """Encrypted chat message exchanged between users or groups."""

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    nonce = db.Column(db.String(24), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    # Optional expiration timestamp used for ephemeral messaging. When set the
    # message is automatically removed once the time has passed.
    expires_at = db.Column(db.DateTime, index=True)
    # ``user_id`` historically referenced the owner of the message.  To support
    # private messaging between two users while maintaining backward
    # compatibility, the original column remains but new ``sender_id`` and
    # ``recipient_id`` fields explicitly store both parties.  ``user_id`` is set
    # to the sender for new messages but is otherwise unused.
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"))
    signature = db.Column(db.String(684), nullable=False)
    read = db.Column(db.Boolean, default=False, nullable=False)


class PinnedKey(db.Model):
    """Fingerprint of a user's public key pinned by another user."""

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    username = db.Column(db.String(64), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False)
    __table_args__ = (
        db.UniqueConstraint("user_id", "username", name="uix_user_pinned"),
    )


class PushToken(db.Model):
    """Store push notification tokens for a user."""

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Web push endpoint or APNs token
    token = db.Column(db.Text, nullable=False)
    platform = db.Column(db.String(16), nullable=False)
    # ``created_at`` records when the token was stored so old entries can be
    # removed automatically by a cleanup job. The timestamp defaults to the
    # current UTC time on insertion.
    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, index=True
    )
    __table_args__ = (
        db.UniqueConstraint("user_id", "token", name="uix_user_token"),
    )
