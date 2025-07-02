"""Simplified double ratchet implementation used for server-side encryption.

This module implements a lightweight symmetric key ratchet providing forward
secrecy for the layer of encryption applied by the server. Each conversation
pair obtains its own :class:`DoubleRatchet` instance keyed by the master
``AES_KEY``. The ratchet derives a new key for every message by combining the
previous root key with a random 32-byte header. Both parties update their root
key after processing a message so past keys are discarded.

The encrypted payload stored in the database consists of the random header
followed by the ciphertext. The associated nonce is stored separately. Clients
never interact with this ratchet directly; it protects the ciphertext sent from
the client to the server.
"""

from __future__ import annotations

import os
from base64 import b64encode, b64decode
from dataclasses import dataclass
from hashlib import sha256
from typing import Dict, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


@dataclass
class DoubleRatchet:
    """Stateful ratchet that derives a new AES key for each message."""

    root_key: bytes

    def _derive_key(self, header: bytes) -> bytes:
        """Return a 32-byte AES key derived from ``root_key`` and ``header``."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.root_key,
            info=header,
            backend=default_backend(),
        )
        return hkdf.derive(b"")

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypt ``plaintext`` and rotate the root key.

        Returns a tuple of ``ciphertext`` (header + encrypted bytes) and ``nonce``.
        """
        header = os.urandom(32)
        nonce = os.urandom(12)
        key = self._derive_key(header)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, plaintext, None)
        # The root key is only advanced when the peer decrypts so both sides
        # remain in sync until the ciphertext has been processed.
        return header + ciphertext, nonce

    def decrypt(self, data: bytes, nonce: bytes) -> bytes:
        """Decrypt ``data`` using the current root key and update it."""
        header, ciphertext = data[:32], data[32:]
        key = self._derive_key(header)
        aes = AESGCM(key)
        plaintext = aes.decrypt(nonce, ciphertext, None)
        # Advance the root key so subsequent messages use a fresh key.
        self.root_key = sha256(self.root_key + header).digest()
        return plaintext


class RatchetStore:
    """In-memory collection of ratchets keyed by sender and receiver."""

    def __init__(self, master_key: bytes):
        self.master_key = master_key
        self._store: Dict[Tuple[str, str], DoubleRatchet] = {}

    def _initial_root(self, a: str, b: str) -> bytes:
        """Derive a deterministic root key for the conversation."""
        info = f"{a}:{b}".encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(self.master_key)

    def get(self, sender: str, receiver: str) -> DoubleRatchet:
        """Return the ratchet used when ``sender`` sends to ``receiver``."""
        key = (sender, receiver)
        if key not in self._store:
            self._store[key] = DoubleRatchet(self._initial_root(*key))
        return self._store[key]


# Global store used by resources. The AES_KEY constant is imported lazily to
# avoid circular imports during application startup.
_store: RatchetStore | None = None


def get_ratchet(sender: str, receiver: str) -> DoubleRatchet:
    """Return the :class:`DoubleRatchet` for ``sender`` -> ``receiver``."""
    global _store
    if _store is None:
        from .resources import AES_KEY  # type: ignore

        _store = RatchetStore(AES_KEY)
    return _store.get(sender, receiver)
