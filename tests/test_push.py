"""Push notification helper tests.

This suite validates encryption handling for push notification tokens including
legacy plaintext storage and corrupted ciphertext.
"""

from base64 import b64decode, b64encode

import backend.resources as res
from backend.models import PushToken


def test_push_token_encryption_roundtrip():
    """Tokens should encrypt and decrypt transparently."""
    plaintext = "tok123"
    enc = PushToken.encrypt_value(plaintext)
    assert plaintext == PushToken.decrypt_value(enc)
    assert enc != plaintext


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

