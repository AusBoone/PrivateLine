"""Password protected channels built on AES encryption.

A password channel is a lightweight construct that allows two or more
users to exchange messages encrypted with a key derived from a shared
password. Channels do not persist in the database in this simplified
implementation; instead ``PasswordChannel`` merely exposes helper
functions for deriving keys and encrypting/decrypting payloads.

The key is derived via PBKDF2-HMAC-SHA256 using a random salt. The
channel participants must remember the password and salt in order to
communicate.

Modification:
    Added explicit error handling in :func:`PasswordChannel.decrypt` to
    translate ``InvalidTag`` exceptions from the cryptography library
    into a ``ValueError`` with a clear message. This ensures callers are
    informed that decryption failed due to authentication issues.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


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
        """Decrypt ``ct_b64`` with the given ``password``.

        Parameters
        ----------
        password:
            The shared channel password from which the AES-GCM key is derived.
        nonce_b64:
            Base64 encoded nonce used during encryption.
        ct_b64:
            Base64 encoded ciphertext (includes the authentication tag).

        Returns
        -------
        bytes
            The decrypted plaintext if authentication succeeds.

        Raises
        ------
        ValueError
            If authentication fails (e.g., because the password, nonce, or
            ciphertext is incorrect). The underlying ``InvalidTag`` exception
            from cryptography is converted into this ``ValueError`` to provide a
            cleaner API for callers.
        """
        # Derive the encryption key from the supplied password and our stored
        # salt. PBKDF2 with SHA-256 and a high iteration count slows brute-force
        # attempts.
        key = self._derive_key(password)
        aes = AESGCM(key)
        nonce = base64.b64decode(nonce_b64)
        ct = base64.b64decode(ct_b64)

        try:
            # AESGCM will raise ``InvalidTag`` when the authentication tag does
            # not match, indicating the ciphertext or password is wrong. We
            # translate this into a ``ValueError`` so callers don't need to
            # depend on the cryptography-specific exception type.
            return aes.decrypt(nonce, ct, None)
        except InvalidTag as exc:
            raise ValueError("decryption failed") from exc
