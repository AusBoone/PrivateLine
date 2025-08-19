"""Validation tests for response headers and CORS behaviour.

This module exercises the backend's handling of security-related HTTP headers
and verifies that cross-origin requests are rejected unless explicitly allowed
via the ``CORS_ORIGINS`` environment variable. Tests focus on typical cases and
regressions that could weaken browser-side protections.
"""

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


def test_cors_rejects_unlisted_origin(client):
    """Requests from origins not listed in CORS_ORIGINS must not receive CORS headers."""
    # The test client inherits the default configuration where ``CORS_ORIGINS``
    # was never set. Any cross-origin request should therefore be ignored by the
    # server because no allowed origins are known.
    resp = client.get("/api/openapi.yaml", headers={"Origin": "http://evil.com"})

    # Flask-CORS leaves the ``Access-Control-Allow-Origin`` header unset in this
    # case, prompting browsers to block the response from being read by scripts
    # running on untrusted origins.
    assert "Access-Control-Allow-Origin" not in resp.headers
