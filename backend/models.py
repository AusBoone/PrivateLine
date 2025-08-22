"""SQLAlchemy models for PrivateLine.

This module defines the database schema used by the Flask backend.
Recent updates add support for per-conversation message retention. Groups may
specify ``retention_days`` while direct chats store a per-recipient policy in
``ConversationRetention``. Scheduled tasks in :mod:`app` rely on these values to
purge old messages.

2027 update: :class:`File` now tracks ``uploader_id`` so attachments cannot be
reused by unauthorized users before a message claims them.
2029 update: :class:`PushToken.token` gracefully handles legacy plaintext
entries and logs unexpected decryption failures.
2031 update: :class:`PushToken` now uses a random nonce and stored hash to
deduplicate tokens without leaking plaintext.
"""

from .app import db
from datetime import datetime
from sqlalchemy.ext.hybrid import hybrid_property
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
import logging
import os
from base64 import b64encode, b64decode
from binascii import Error as BinasciiError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256
from sqlalchemy.orm.attributes import InstrumentedAttribute

# AES-256 key used to encrypt push notification tokens. It mirrors the
# ``AES_KEY`` defined in :mod:`backend.resources` so encrypted values remain
# compatible across modules.
_aes_env = os.environ.get("AES_KEY")
if not _aes_env:
    raise RuntimeError("AES_KEY environment variable not set")
AES_KEY = b64decode(_aes_env)
_aesgcm = AESGCM(AES_KEY)

# Default age in days before uploaded files are eligible for deletion. The
# setting mirrors ``FILE_RETENTION_DAYS`` from :mod:`backend.app` so tests can
# override it via the environment. Each :class:`File` instance stores the
# effective retention period to support per-file overrides in the future.
FILE_RETENTION_DAYS = int(os.environ.get("FILE_RETENTION_DAYS", "30"))


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
    message_retention_days = db.Column(db.Integer, nullable=False, server_default="30")

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
    # Optional retention period for messages in this group. When ``None``
    # each member's personal ``message_retention_days`` setting is used
    # instead.
    retention_days = db.Column(db.Integer)


class GroupMember(db.Model):
    """Association table linking users to groups."""

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class ConversationRetention(db.Model):
    """Custom retention policy for a direct conversation."""

    id = db.Column(db.Integer, primary_key=True)
    # User who defined the policy
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Peer this policy applies to
    peer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Number of days to keep read messages
    retention_days = db.Column(db.Integer, nullable=False)
    __table_args__ = (
        db.UniqueConstraint("owner_id", "peer_id", name="uix_conv_retention"),
    )


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
    # Timestamp when the file was uploaded. Used to enforce retention policies
    # via the ``clean_expired_files`` scheduled job.
    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, index=True
    )
    # Maximum age for this file in days. Defaults to ``FILE_RETENTION_DAYS`` but
    # can be overridden per-file if needed.
    file_retention_days = db.Column(
        db.Integer, nullable=False, server_default=str(FILE_RETENTION_DAYS)
    )
    # Maximum number of times this file may be downloaded before it is deleted.
    # The value defaults to ``1`` so attachments are ephemeral unless the value
    # is increased via a database migration or manual update.
    max_downloads = db.Column(db.Integer, nullable=False, server_default="1")
    # Counter tracking how many times the file has been retrieved. ``download_count``
    # increments on each successful GET request and is compared against
    # ``max_downloads`` to determine when the file should be removed.
    download_count = db.Column(db.Integer, nullable=False, server_default="0")
    # ``uploader_id`` records the user who originally uploaded the file so that
    # ownership can be enforced before any message references exist. The value
    # is always set by :class:`~backend.resources.FileUpload` during upload.
    uploader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Optional additional authenticated data used during AES-GCM encryption of
    # the file. The value stores the concatenated message identifier and
    # recipient information so downloads can verify the metadata has not been
    # tampered with. ``None`` indicates that no AAD was supplied at upload time.
    aad = db.Column(db.String(128))


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
    # When ``delete_on_read`` is true the message is removed as soon as it is
    # marked read. This supports disappearing messages in private chats.
    delete_on_read = db.Column(
        db.Boolean, nullable=False, server_default="false", index=True
    )


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
    """Store push notification tokens for a user.

    Tokens are encrypted with AES-GCM using a **random 12-byte nonce** so the
    database never stores plaintext push identifiers. The nonce is prefixed to
    the ciphertext before base64 encoding. Because random nonces produce unique
    ciphertext for identical tokens, a SHA-256 ``token_hash`` column tracks a
    deterministic digest to enforce uniqueness per user without revealing the
    original token.
    """

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Encrypted push token stored as base64 nonce+ciphertext
    token_ciphertext = db.Column("token", db.Text, nullable=False)
    # SHA-256 hash of the plaintext token used for deduplication
    token_hash = db.Column(db.String(64), nullable=False, index=True)
    platform = db.Column(db.String(16), nullable=False)
    # ``created_at`` records when the token was stored so old entries can be
    # removed automatically by a cleanup job. The timestamp defaults to the
    # current UTC time on insertion.
    created_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, index=True
    )
    __table_args__ = (
        db.UniqueConstraint("user_id", "token_hash", name="uix_user_token"),
    )

    # --- Encryption helpers -------------------------------------------------
    @staticmethod
    def _generate_nonce() -> bytes:
        """Return a cryptographically secure random 12-byte nonce."""
        return os.urandom(12)

    @classmethod
    def encrypt_value(cls, token: str) -> str:
        """Return base64-encoded nonce+ciphertext for ``token``."""
        nonce = cls._generate_nonce()
        ciphertext = _aesgcm.encrypt(nonce, token.encode(), None)
        return b64encode(nonce + ciphertext).decode()

    @classmethod
    def decrypt_value(cls, data: str) -> str:
        """Return the decrypted token from ``data``."""
        raw = b64decode(data)
        nonce, ct = raw[:12], raw[12:]
        return _aesgcm.decrypt(nonce, ct, None).decode()

    @hybrid_property
    def token(self) -> str:
        """Plaintext push token.

        The database column ``token_ciphertext`` stores the push identifier in
        one of two formats:

        * **Encrypted, base64 encoded** – the modern format consisting of a
          12-byte nonce followed by AES-GCM ciphertext. These values are
          decrypted transparently.
        * **Legacy plaintext** – older rows stored the token directly without
          encryption. These values are returned unchanged to preserve backward
          compatibility.

        Corrupted or tampered encrypted values that fail decryption likewise
        fall back to the raw stored string. Unexpected errors are logged for
        diagnostic purposes.
        """

        data = self.token_ciphertext

        # When accessed on the class (e.g., inside queries) ``data`` is an
        # ``InstrumentedAttribute`` representing the underlying column. In this
        # context we simply return the column object so SQLAlchemy can build the
        # appropriate SQL expression.
        if isinstance(data, InstrumentedAttribute):
            return data

        # Detect legacy plaintext rows by validating and decoding the base64
        # representation first. ``validate=True`` rejects non-base64 characters
        # so plaintext tokens fall through to the ``except`` block below.
        try:
            raw = b64decode(data, validate=True)
        except BinasciiError:
            return data

        # Decrypt the base64 decoded value. The first 12 bytes store the nonce
        # followed by the AES-GCM ciphertext.
        try:
            nonce, ct = raw[:12], raw[12:]
            return _aesgcm.decrypt(nonce, ct, None).decode()
        except InvalidTag:
            return data
        except Exception:  # Unexpected failure: log and return stored value
            logging.exception("Unexpected error decrypting push token")
            return data

    @token.setter
    def token(self, value: str) -> None:
        """Encrypt ``value`` and store ciphertext and hash.

        An empty token is rejected to avoid storing meaningless values.
        """
        if not value:
            raise ValueError("Token must be non-empty")
        self.token_ciphertext = self.encrypt_value(value)
        self.token_hash = sha256(value.encode()).hexdigest()
