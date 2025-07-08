"""Utilities for Curve25519-based end-to-end encryption.

This module exposes helpers used by the application to perform E2E
encryption and decryption using ephemeral Curve25519 key exchange and
AES-GCM for the symmetric cipher. The intent is that messages are
encrypted client-side before being transmitted to the server. The server
simply stores the ciphertext.

Example usage:

>>> priv_a, pub_a = generate_keypair()
>>> priv_b, pub_b = generate_keypair()
>>> enc = encrypt_message(b"hi", pub_b)
>>> msg = decrypt_message(enc, priv_b)
>>> assert msg == b"hi"

The ``encrypt_message`` function returns a dictionary containing the
base64 encoded ciphertext, nonce, and ephemeral public key. The receiver
uses ``decrypt_message`` with their private key to recover the plaintext.

Design notes:
- HKDF derives a 32-byte AES key from the shared secret.
- A new ephemeral key is generated for every encryption operation to
  provide forward secrecy.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Dict
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization


@dataclass
class EncryptedMessage:
    """Container holding encrypted message fields."""

    ciphertext_b64: str
    nonce_b64: str
    ephemeral_pub_b64: str


def generate_keypair() -> tuple[X25519PrivateKey, str]:
    """Return a new Curve25519 private key and its public component.

    The public key is encoded using base64 for easy transport. The private
    key object is returned directly as it is used for decryption.
    """

    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, base64.b64encode(pub).decode()


def _derive_aes_key(shared: bytes) -> bytes:
    """Derive a 256-bit AES key from the ECDH shared secret."""

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"e2e-msg",
    )
    return hkdf.derive(shared)


def encrypt_message(plaintext: bytes, recipient_pub_b64: str) -> EncryptedMessage:
    """Encrypt ``plaintext`` for ``recipient_pub_b64``.

    Parameters
    ----------
    plaintext:
        Raw bytes to encrypt.
    recipient_pub_b64:
        Base64 encoded public key of the recipient.

    Returns
    -------
    EncryptedMessage
        Object containing base64 fields required for decryption.
    """

    recipient_pub = X25519PublicKey.from_public_bytes(base64.b64decode(recipient_pub_b64))
    ephemeral_priv = X25519PrivateKey.generate()
    shared = ephemeral_priv.exchange(recipient_pub)
    aes_key = _derive_aes_key(shared)

    aes = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext, None)

    return EncryptedMessage(
        ciphertext_b64=base64.b64encode(ciphertext).decode(),
        nonce_b64=base64.b64encode(nonce).decode(),
        ephemeral_pub_b64=base64.b64encode(
            ephemeral_priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode(),
    )


def decrypt_message(data: EncryptedMessage, recipient_priv: X25519PrivateKey) -> bytes:
    """Return the decrypted plaintext for ``data`` using ``recipient_priv``."""

    ephemeral_pub = X25519PublicKey.from_public_bytes(
        base64.b64decode(data.ephemeral_pub_b64)
    )
    shared = recipient_priv.exchange(ephemeral_pub)
    aes_key = _derive_aes_key(shared)

    aes = AESGCM(aes_key)
    nonce = base64.b64decode(data.nonce_b64)
    ciphertext = base64.b64decode(data.ciphertext_b64)
    return aes.decrypt(nonce, ciphertext, None)
