"""Push notification helper tests."""

import backend.resources as res
from backend.models import PushToken


def test_push_token_encryption_roundtrip():
    """Tokens should encrypt and decrypt transparently."""
    plaintext = "tok123"
    enc = PushToken.encrypt_value(plaintext)
    assert plaintext == PushToken.decrypt_value(enc)
    assert enc != plaintext


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

