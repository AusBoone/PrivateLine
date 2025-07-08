import base64
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
