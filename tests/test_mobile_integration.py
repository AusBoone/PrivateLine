"""Cross-platform mobile messaging integration tests.

These tests simulate iOS and Android clients exchanging encrypted messages using
an identical payload. They confirm that push-token registration stores the
platform correctly and that real-time WebSocket delivery emits events to the
appropriate user rooms. Run with ``pytest``.
"""

import base64

import pytest

import backend.resources as res
from backend.app import app, socketio
from backend.models import PushToken, User
from .conftest import (
    register_user,
    login_user,
    decrypt_private_key,
    sign_content,
)


@pytest.fixture
def payload():
    """Return a base64-encoded plaintext shared by both mobile clients.

    Using the same fixture for iOS and Android ensures both platforms exercise
    identical message content, catching discrepancies hidden by divergent test
    data.
    """
    return base64.b64encode(b"hello from integration").decode()


def test_ios_android_message_exchange(client, payload, monkeypatch):
    """End-to-end message exchange between iOS and Android clients.

    The test performs the following flow:

    * Register iOS and Android users and obtain their private keys.
    * Each user registers a push token for their respective platform.
    * ``socketio.emit`` is patched to capture real-time events instead of
      establishing actual WebSocket connections.
    * Android sends a message to iOS, then iOS replies using the shared
      payload.
    * ``send_apns`` and ``send_fcm`` are patched so we can assert push
      notifications are triggered for the correct tokens.
    * Emitted events and push invocations are validated for both directions.
    """
    # ------------------------------------------------------------------
    # User setup: create two users and decrypt their private keys so messages
    # can be signed exactly as mobile apps would.
    reg_ios = register_user(client, "ios_user")
    reg_android = register_user(client, "android_user")
    pk_ios = decrypt_private_key(reg_ios)
    pk_android = decrypt_private_key(reg_android)

    # Acquire JWTs for authenticated API requests.
    token_ios = login_user(client, "ios_user").get_json()["access_token"]
    token_android = login_user(client, "android_user").get_json()["access_token"]
    headers_ios = {"Authorization": f"Bearer {token_ios}"}
    headers_android = {"Authorization": f"Bearer {token_android}"}

    # ------------------------------------------------------------------
    # Push-token registration: store platform-specific tokens for each user.
    client.post(
        "/api/push-token",
        json={"token": "tok-ios", "platform": "ios"},
        headers=headers_ios,
    )
    client.post(
        "/api/push-token",
        json={"token": "tok-android", "platform": "android"},
        headers=headers_android,
    )

    # Confirm tokens were persisted and associated with the correct platform.
    with app.app_context():
        ios_token = PushToken.query.filter_by(platform="ios").first()
        android_token = PushToken.query.filter_by(platform="android").first()
        assert ios_token is not None and ios_token.token == "tok-ios"
        assert android_token is not None and android_token.token == "tok-android"
        ios_id = User.query.filter_by(username="ios_user").first().id
        android_id = User.query.filter_by(username="android_user").first().id

    # ------------------------------------------------------------------
    # Patch push notification helpers to record invocations instead of making
    # network requests to external services.
    apns_calls = {}
    fcm_calls = {}

    def fake_apns(token: str, message: str) -> None:
        """Capture APNs usage for assertions."""
        apns_calls["token"] = token
        apns_calls["message"] = message

    def fake_fcm(token: str, message: str) -> None:
        """Capture FCM usage for assertions."""
        fcm_calls["token"] = token
        fcm_calls["message"] = message

    monkeypatch.setattr(res, "send_apns", fake_apns)
    monkeypatch.setattr(res, "send_fcm", fake_fcm)

    # Patch ``socketio.emit`` to capture real-time message broadcasts.
    emitted = []

    def fake_emit(event: str, data=None, to=None, **kwargs) -> None:
        emitted.append({"event": event, "data": data, "to": to})

    monkeypatch.setattr(socketio, "emit", fake_emit)

    # ------------------------------------------------------------------
    # Android -> iOS: send a message and validate emission and push handling.
    sig_android = sign_content(pk_android, payload)
    client.post(
        "/api/messages",
        data={"content": payload, "recipient": "ios_user", "signature": sig_android},
        headers=headers_android,
    )
    assert any(
        e["event"] == "new_message"
        and e["data"]["content"] == payload
        and e["to"] == str(ios_id)
        for e in emitted
    )
    assert apns_calls["token"] == "tok-ios"
    assert apns_calls["message"] == "New message"
    emitted.clear()

    # ------------------------------------------------------------------
    # iOS -> Android: send a reply and check emission and push handling.
    sig_ios = sign_content(pk_ios, payload)
    client.post(
        "/api/messages",
        data={"content": payload, "recipient": "android_user", "signature": sig_ios},
        headers=headers_ios,
    )
    assert any(
        e["event"] == "new_message"
        and e["data"]["content"] == payload
        and e["to"] == str(android_id)
        for e in emitted
    )
    assert fcm_calls["token"] == "tok-android"
    assert fcm_calls["message"] == "New message"
