from .app import db
from datetime import datetime
from sqlalchemy.ext.hybrid import hybrid_property
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.hazmat.backends import default_backend

"""
When a new user is registered, a public-private key pair is generated.
The public key is stored in the User model, and the private key is sent to the user.

See 'Register' resource in 'resources.py'
"""
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key_pem = db.Column(db.Text, nullable=False)

    @hybrid_property
    def public_key(self):
        return serialization.load_pem_public_key(self.public_key_pem.encode(), default_backend())

    @staticmethod
    def generate_key_pair():
        """Return a new RSA private key and the corresponding public key PEM."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode()

        return private_key, public_key_pem


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)


class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(256), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    nonce = db.Column(db.String(24), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    # ``user_id`` historically referenced the owner of the message.  To support
    # private messaging between two users while maintaining backward
    # compatibility, the original column remains but new ``sender_id`` and
    # ``recipient_id`` fields explicitly store both parties.  ``user_id`` is set
    # to the sender for new messages but is otherwise unused.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'))


class PinnedKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(64), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False)
    __table_args__ = (
        db.UniqueConstraint('user_id', 'username', name='uix_user_pinned'),
    )


class PushToken(db.Model):
    """Store push notification tokens for a user."""

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.Text, nullable=False)
    platform = db.Column(db.String(16), nullable=False)
    __table_args__ = (
        db.UniqueConstraint('user_id', 'token', name='uix_user_token'),
    )
