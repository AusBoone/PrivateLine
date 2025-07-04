import os
import base64
import importlib

from backend.app import app
from .conftest import register_user, login_user


def test_default_security_headers(client):
    """Responses should include basic security headers by default."""
    register_user(client, "alice")
    token = login_user(client, "alice").get_json()["access_token"]
    resp = client.get(
        "/api/messages", headers={"Authorization": f"Bearer {token}"}
    )
    headers = resp.headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"
    assert "Content-Security-Policy" in headers
    assert "Strict-Transport-Security" not in headers


def test_hsts_enabled(monkeypatch, client):
    """Strict-Transport-Security should be sent when HSTS_ENABLED is true."""
    monkeypatch.setenv("HSTS_ENABLED", "true")
    resp = client.get("/api/openapi.yaml")
    assert resp.headers["Strict-Transport-Security"].startswith("max-age=")
