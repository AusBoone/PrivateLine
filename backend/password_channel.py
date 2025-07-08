"""Password protected channels built on AES encryption.

A password channel is a lightweight construct that allows two or more
users to exchange messages encrypted with a key derived from a shared
password. Channels do not persist in the database in this simplified
implementation; instead ``PasswordChannel`` merely exposes helper
functions for deriving keys and encrypting/decrypting payloads.

The key is derived via PBKDF2-HMAC-SHA256 using a random salt. The
channel participants must remember the password and salt in order to
communicate.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class PasswordChannel:
    """Represents a channel protected by a password."""

    salt_b64: str
    iterations: int = 200_000

    def _derive_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=base64.b64decode(self.salt_b64),
            iterations=self.iterations,
        )
        return kdf.derive(password.encode())

    @classmethod
    def create(cls) -> "PasswordChannel":
        """Return a new channel with a random salt."""
        salt = os.urandom(16)
        return cls(base64.b64encode(salt).decode())

    def encrypt(self, password: str, plaintext: bytes) -> tuple[str, str]:
        """Encrypt ``plaintext`` using ``password``.

        Returns a tuple ``(nonce_b64, ciphertext_b64)``.
        """
        key = self._derive_key(password)
        nonce = os.urandom(12)
        aes = AESGCM(key)
        ct = aes.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode()

    def decrypt(self, password: str, nonce_b64: str, ct_b64: str) -> bytes:
        """Decrypt ``ct_b64`` with the given ``password``."""
        key = self._derive_key(password)
        aes = AESGCM(key)
        nonce = base64.b64decode(nonce_b64)
        ct = base64.b64decode(ct_b64)
        return aes.decrypt(nonce, ct, None)
