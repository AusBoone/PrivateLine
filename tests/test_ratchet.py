"""Double ratchet unit tests."""

import base64

from backend.ratchet import DoubleRatchet


def test_ratchet_rotation():
    """Keys should rotate after each encrypt/decrypt cycle."""
    dr = DoubleRatchet(b"0" * 32)
    first_key = dr.root_key
    ct, nonce = dr.encrypt(b"hello")
    # Encryption should not advance the key until a peer decrypts
    assert dr.root_key == first_key
    pt = dr.decrypt(ct, nonce)
    assert pt == b"hello"
    second_key = dr.root_key
    assert second_key != first_key
    ct2, nonce2 = dr.encrypt(b"bye")
    assert dr.root_key == second_key
    pt2 = dr.decrypt(ct2, nonce2)
    assert pt2 == b"bye"

