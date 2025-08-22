"""Push notification helper tests.

This suite validates encryption handling for push notification tokens including
legacy plaintext storage, corrupted ciphertext, and the new random nonce and
hash-based deduplication scheme. Additional tests ensure that when a token is
re-registered with a different platform the existing database row is updated
instead of creating a duplicate, proving deduplication relies on the token's
SHA-256 hash rather than ciphertext.
"""

from base64 import b64decode, b64encode
from hashlib import sha256

import backend.resources as res
from backend.models import PushToken


def test_push_token_encryption_roundtrip():
    """Tokens should encrypt and decrypt transparently."""
    plaintext = "tok123"
    enc = PushToken.encrypt_value(plaintext)
    assert plaintext == PushToken.decrypt_value(enc)
    assert enc != plaintext


def test_push_token_random_nonce():
    """Repeated encryption should yield distinct ciphertext due to random nonce."""
    token = "tok123"
    first = PushToken.encrypt_value(token)
    second = PushToken.encrypt_value(token)
    # Even though the nonce is random, decryption must still recover the original
    # plaintext for both ciphertexts.
    assert first != second
    assert PushToken.decrypt_value(first) == token
    assert PushToken.decrypt_value(second) == token


def test_push_token_legacy_plaintext():
    """Legacy plaintext values are returned unchanged."""
    pt = PushToken(token_ciphertext="legacy", user_id=1, platform="web")
    assert pt.token == "legacy"


def test_push_token_corrupted_data():
    """Corrupted ciphertext falls back to the stored base64 string."""
    good = PushToken.encrypt_value("abc")
    raw = bytearray(b64decode(good))
    raw[-1] ^= 1  # Flip a bit to invalidate the auth tag
    corrupted = b64encode(raw).decode()
    pt = PushToken(token_ciphertext=corrupted, user_id=1, platform="web")
    assert pt.token == corrupted


def test_fcm_request(monkeypatch):
    """An Android token should trigger a request to FCM."""
    called = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        called['url'] = url
        called['json'] = json
        called['headers'] = headers
        return type('Resp', (), {'status_code': 200})

    monkeypatch.setenv('FCM_SERVER_KEY', 'secret')
    monkeypatch.setattr('requests.post', fake_post)

    res.send_fcm('token123', 'hi')

    assert called['url'] == 'https://fcm.googleapis.com/fcm/send'
    assert called['json']['to'] == 'token123'
    assert called['headers']['Authorization'] == 'key=secret'


def test_push_token_db_encrypted(client):
    """Stored tokens should not be plaintext in the database."""
    from .conftest import register_user, login_user
    from backend.app import app

    register_user(client, "alice")
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post(
        "/api/push-token", json={"token": "abc", "platform": "web"}, headers=headers
    )

    with app.app_context():
        pt = PushToken.query.first()
        assert pt.token == "abc"
        assert pt.token_ciphertext != "abc"
        # The SHA-256 hash should be stored to facilitate deduplication.
        assert pt.token_hash == sha256(b"abc").hexdigest()


def test_push_token_deduplication(client):
    """Reposting the same token should not create duplicate rows."""
    from .conftest import register_user, login_user
    from backend.app import app

    register_user(client, "alice")
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Store the token twice; the second request should update the existing row
    # rather than inserting a duplicate because uniqueness is enforced via
    # ``token_hash``.
    client.post(
        "/api/push-token", json={"token": "dup", "platform": "web"}, headers=headers
    )
    client.post(
        "/api/push-token", json={"token": "dup", "platform": "web"}, headers=headers
    )

    with app.app_context():
        assert PushToken.query.count() == 1


def test_push_token_platform_update(client):
    """Changing the platform resubmits the token without duplicating rows."""
    from .conftest import register_user, login_user
    from backend.app import app

    register_user(client, "alice")
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Register the token as an iOS device and then again as Android. The hash
    # remains identical, so the second request should update the platform field
    # on the existing row rather than insert a new record.
    client.post(
        "/api/push-token", json={"token": "dup", "platform": "ios"}, headers=headers
    )
    client.post(
        "/api/push-token", json={"token": "dup", "platform": "android"}, headers=headers
    )

    with app.app_context():
        pts = PushToken.query.all()
        assert len(pts) == 1
        assert pts[0].platform == "android"

