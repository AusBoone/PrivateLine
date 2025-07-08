"""Data migration to encrypt stored push notification tokens.

Existing tokens are read in plaintext, encrypted using the same AES-GCM
mechanism employed by :class:`backend.models.PushToken`, and written back to
the ``push_token`` table. The migration requires the ``AES_KEY`` environment
variable to be present so the ciphertext can be generated deterministically.
"""

from alembic import op
import sqlalchemy as sa
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256
import os

revision = '2c'
down_revision = '1b'
branch_labels = None
depends_on = None


def _aesgcm():
    key_b64 = os.environ.get('AES_KEY')
    if not key_b64:
        raise RuntimeError('AES_KEY environment variable not set')
    return AESGCM(b64decode(key_b64))


def upgrade():
    """Encrypt all rows in the ``push_token`` table."""
    conn = op.get_bind()
    aes = _aesgcm()
    tokens = conn.execute(sa.text("SELECT id, token FROM push_token")).fetchall()
    for tid, plaintext in tokens:
        nonce = sha256(plaintext.encode()).digest()[:12]
        ct = aes.encrypt(nonce, plaintext.encode(), None)
        enc = b64encode(nonce + ct).decode()
        conn.execute(
            sa.text("UPDATE push_token SET token=:t WHERE id=:i"),
            {"t": enc, "i": tid},
        )


def downgrade():
    """Revert tokens back to plaintext form."""
    conn = op.get_bind()
    aes = _aesgcm()
    tokens = conn.execute(sa.text("SELECT id, token FROM push_token")).fetchall()
    for tid, enc in tokens:
        raw = b64decode(enc)
        nonce, ct = raw[:12], raw[12:]
        plain = aes.decrypt(nonce, ct, None).decode()
        conn.execute(
            sa.text("UPDATE push_token SET token=:t WHERE id=:i"),
            {"t": plain, "i": tid},
        )

