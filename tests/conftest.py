"""Shared fixtures and helpers for PrivateLine tests."""

import os
import base64
import io
import pytest
from base64 import b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Ensure deterministic keys for tests
os.environ.setdefault("AES_KEY", base64.b64encode(os.urandom(32)).decode())
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")

from backend.app import app, db, RedisBlocklist, limiter
from backend.models import User


@pytest.fixture(autouse=True)
def fake_blocklist(monkeypatch):
    """Provide an in-memory token blocklist for tests."""
    import fakeredis

    blocklist = RedisBlocklist(fakeredis.FakeRedis())
    monkeypatch.setattr("backend.app.token_blocklist", blocklist)
    monkeypatch.setattr("backend.resources.token_blocklist", blocklist)
    yield


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Reset request counters between tests to avoid cross-test bleed."""
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def client():
    """Flask test client with an isolated SQLite database."""
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.app_context():
        db.create_all()
    with app.test_client() as client:
        yield client
    with app.app_context():
        db.drop_all()


# --- Helper utilities ------------------------------------------------------


def register_user(client, username="alice"):
    """Register ``username`` with a default password."""
    data = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "secret",
    }
    return client.post("/api/register", data=data)


def login_user(client, username="alice"):
    """Log ``username`` in and return the response."""
    return client.post("/api/login", json={"username": username, "password": "secret"})


def decrypt_private_key(resp):
    """Return the private key from a registration response."""
    from cryptography.hazmat.primitives import serialization

    data = resp.get_json()
    salt = b64decode(data["salt"])
    nonce = b64decode(data["nonce"])
    ciphertext = b64decode(data["encrypted_private_key"])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend(),
    )
    key = kdf.derive(b"secret")
    pem = AESGCM(key).decrypt(nonce, ciphertext, None)
    return serialization.load_pem_private_key(pem, password=None)


def sign_content(private_key, content: str) -> str:
    """Sign ``content`` with ``private_key`` and return base64 signature."""
    from cryptography.hazmat.primitives.asymmetric import padding as asympad

    sig = private_key.sign(
        content.encode(),
        asympad.PSS(
            mgf=asympad.MGF1(hashes.SHA256()), salt_length=asympad.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()
