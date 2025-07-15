"""Cryptography helper tests.

These unit tests exercise the helper routines used for end-to-end encryption.
They confirm that normal encryption/decryption succeeds and that tampering or
using the wrong key fails as expected. Run with ``pytest``.
"""

import base64
import pytest
from backend.crypto_e2e import generate_keypair, encrypt_message, decrypt_message
from backend.password_channel import PasswordChannel


def test_curve25519_e2e_roundtrip():
    """Encryption and decryption with Curve25519 should round-trip."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()

    msg = b"secret"
    enc = encrypt_message(msg, pub_b)
    dec = decrypt_message(enc, priv_b)
    assert dec == msg


def test_password_channel_encryption():
    """Password channels encrypt and decrypt data symmetrically."""
    channel = PasswordChannel.create()
    password = "hunter2"
    nonce, ct = channel.encrypt(password, b"top")
    pt = channel.decrypt(password, nonce, ct)
    assert pt == b"top"


def test_decrypt_message_wrong_key():
    """Decrypting with a non-matching private key should fail."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    enc = encrypt_message(b"data", pub_b)
    with pytest.raises(Exception):
        decrypt_message(enc, priv_a)


def test_decrypt_message_tampered_ciphertext():
    """Altering ciphertext should raise an authentication error."""
    priv_a, pub_a = generate_keypair()
    enc = encrypt_message(b"bits", pub_a)
    # Flip one byte of the ciphertext to invalidate the tag
    broken = enc.ciphertext_b64[:-2] + ("A" if enc.ciphertext_b64[-1] != "A" else "B")
    tampered = enc.__class__(
        ciphertext_b64=broken,
        nonce_b64=enc.nonce_b64,
        ephemeral_pub_b64=enc.ephemeral_pub_b64,
    )
    with pytest.raises(Exception):
        decrypt_message(tampered, priv_a)
