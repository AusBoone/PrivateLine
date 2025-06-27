"""Authentication and account management tests for PrivateLine."""

import base64
import io

from backend.app import app
from backend.models import User, PushToken
from .conftest import (
    register_user,
    login_user,
    decrypt_private_key,
    sign_content,
)


def test_register_missing_fields(client):
    resp = client.post("/api/register", data={"username": "x"})
    assert resp.status_code == 400


def test_login_invalid_credentials(client):
    register_user(client, "dave")
    resp = client.post("/api/login", json={"username": "dave", "password": "bad"})
    assert resp.status_code == 401


def test_register_duplicate_email(client):
    register_user(client, "alice")
    resp = client.post(
        "/api/register",
        data={"username": "bob", "email": "alice@example.com", "password": "secret"},
    )
    assert resp.status_code == 400


def test_register_and_login(client):
    resp = register_user(client)
    assert resp.status_code == 201
    payload = resp.get_json()
    assert {"encrypted_private_key", "salt", "nonce", "fingerprint"} <= payload.keys()

    user = User.query.filter_by(username="alice").first()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import hashlib

    der = user.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    expected_fp = hashlib.sha256(der).hexdigest()
    assert payload["fingerprint"] == expected_fp

    password = "secret".encode()
    salt = base64.b64decode(payload["salt"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["encrypted_private_key"])
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend(),
    )
    key = kdf.derive(password)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    assert plaintext.startswith(b"-----BEGIN PRIVATE KEY-----")

    resp = login_user(client)
    assert resp.status_code == 200
    assert "access_token" in resp.get_json()


def test_account_settings_update(client):
    register_user(client, "carol")
    login = login_user(client, "carol")
    token = login.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.put(
        "/api/account-settings", json={"email": "carol2@example.com"}, headers=headers
    )
    assert resp.status_code == 200

    resp = client.put(
        "/api/account-settings",
        json={"currentPassword": "secret", "newPassword": "newsecret"},
        headers=headers,
    )
    assert resp.status_code == 200

    resp = client.post(
        "/api/login", json={"username": "carol", "password": "newsecret"}
    )
    assert resp.status_code == 200


def test_account_settings_duplicate_email(client):
    """Updating the email to one already in use should return HTTP 400."""
    register_user(client, "eve")
    register_user(client, "frank")

    login = login_user(client, "eve")
    token = login.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.put(
        "/api/account-settings",
        json={"email": "frank@example.com"},
        headers=headers,
    )
    assert resp.status_code == 400


def test_token_refresh(client):
    register_user(client, "frank")
    token = login_user(client, "frank").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post("/api/refresh", headers=headers)
    assert resp.status_code == 200
    new_token = resp.get_json()["access_token"]
    assert new_token != token

    resp = client.get("/api/messages", headers={"Authorization": f"Bearer {new_token}"})
    assert resp.status_code == 200


def test_token_revocation(client):
    register_user(client, "gina")
    token = login_user(client, "gina").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post("/api/revoke", headers=headers)
    assert resp.status_code == 200

    resp = client.get("/api/messages", headers=headers)
    assert resp.status_code == 401

    new_token = login_user(client, "gina").get_json()["access_token"]
    resp = client.get("/api/messages", headers={"Authorization": f"Bearer {new_token}"})
    assert resp.status_code == 200


def test_public_key_endpoint(client):
    register_user(client, "alice")
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    user = User.query.filter_by(username="alice").first()
    resp = client.get("/api/public_key/alice", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["public_key"] == user.public_key_pem


def test_pinned_keys_endpoint(client):
    register_user(client, "alice")
    register_user(client, "bob")

    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    bob_user = User.query.filter_by(username="bob").first()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import hashlib

    der = bob_user.public_key.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    fp = hashlib.sha256(der).hexdigest()

    resp = client.post(
        "/api/pinned_keys", json={"username": "bob", "fingerprint": fp}, headers=headers
    )
    assert resp.status_code == 200
    resp = client.get("/api/pinned_keys", headers=headers)
    assert resp.status_code == 200
    assert {"username": "bob", "fingerprint": fp} in resp.get_json()["pinned_keys"]


def test_push_token_and_notification(monkeypatch, client):
    register_user(client, "alice")
    reg_bob = register_user(client, "bob")
    pk_bob = decrypt_private_key(reg_bob)

    token_alice = login_user(client, "alice").get_json()["access_token"]
    headers_alice = {"Authorization": f"Bearer {token_alice}"}
    resp = client.post(
        "/api/push-token",
        json={"token": "abc", "platform": "web"},
        headers=headers_alice,
    )
    assert resp.status_code == 200

    calls = []
    monkeypatch.setattr(
        "backend.resources.send_push_notifications",
        lambda uid, msg: calls.append((uid, msg)),
    )

    token_bob = login_user(client, "bob").get_json()["access_token"]
    headers_bob = {"Authorization": f"Bearer {token_bob}"}
    b64 = base64.b64encode(b"hi").decode()
    sig = sign_content(pk_bob, b64)
    client.post(
        "/api/messages",
        data={"content": b64, "recipient": "alice", "signature": sig},
        headers=headers_bob,
    )

    assert calls


def test_push_token_delete(client):
    register_user(client, "alice")
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/api/push-token", json={"token": "tok", "platform": "web"}, headers=headers
    )
    assert resp.status_code == 200

    resp = client.delete("/api/push-token", json={"token": "tok"}, headers=headers)
    assert resp.status_code == 200
    with app.app_context():
        assert PushToken.query.filter_by(token="tok").first() is None


def test_users_endpoint(client):
    register_user(client, "alice")
    register_user(client, "bob")
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/users", headers=headers)
    assert resp.status_code == 200
    names = resp.get_json()["users"]
    assert "alice" in names and "bob" in names

    resp = client.get("/api/users?q=bo", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["users"] == ["bob"]


def test_cors_origins_applied(monkeypatch):
    """CORS_ORIGINS should configure both Flask and Socket.IO."""
    monkeypatch.setenv("CORS_ORIGINS", "http://example.com")
    import importlib
    import backend.app as appmod

    appmod = importlib.reload(appmod)

    client = appmod.app.test_client()
    resp = client.options(
        "/api/login",
        headers={
            "Origin": "http://example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert resp.headers["Access-Control-Allow-Origin"] == "http://example.com"
    assert appmod.socketio.server.eio.cors_allowed_origins == ["http://example.com"]


def test_register_rate_limit(client):
    """Exceeding the registration rate limit should return HTTP 429."""
    from backend.app import limiter

    limiter.reset()
    for i in range(10):
        client.post(
            "/api/register",
            data={
                "username": f"u{i}",
                "email": f"u{i}@example.com",
                "password": "secret",
            },
        )
    resp = client.post(
        "/api/register",
        data={
            "username": "extra",
            "email": "extra@example.com",
            "password": "secret",
        },
    )
    assert resp.status_code == 429
    limiter.reset()


def test_login_rate_limit(client):
    """Too many login attempts should trigger rate limiting."""
    from backend.app import limiter

    register_user(client, "hank")
    limiter.reset()
    for _ in range(10):
        client.post("/api/login", json={"username": "hank", "password": "bad"})
    resp = client.post("/api/login", json={"username": "hank", "password": "bad"})
    assert resp.status_code == 429
    limiter.reset()
