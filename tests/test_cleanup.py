"""Verify that expired messages are removed by the background job."""

from datetime import datetime, timedelta
import base64

from backend.app import app, clean_expired_messages, db
from backend.models import Message
from .conftest import register_user, login_user, decrypt_private_key, sign_content


def test_expired_message_cleanup(client):
    """Messages past their expiration should be deleted from the database."""
    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    msg_b64 = base64.b64encode(b"bye").decode()
    sig = sign_content(pk, msg_b64)
    past = (datetime.utcnow() - timedelta(minutes=1)).isoformat()
    resp = client.post(
        "/api/messages",
        data={
            "content": msg_b64,
            "recipient": "alice",
            "signature": sig,
            "expires_at": past,
        },
        headers=headers,
    )
    assert resp.status_code == 201
    mid = resp.get_json()["id"]

    with app.app_context():
        assert db.session.get(Message, mid) is not None

    clean_expired_messages()

    with app.app_context():
        assert db.session.get(Message, mid) is None


def test_read_message_retention(client):
    """Read messages older than the user's retention should be purged."""
    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    b64 = base64.b64encode(b"old").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "alice", "signature": sig},
        headers=headers,
    )
    mid = resp.get_json()["id"]
    client.post(f"/api/messages/{mid}/read", headers=headers)

    # Retain read messages for only one day
    client.put(
        "/api/account-settings",
        json={"messageRetentionDays": 1},
        headers=headers,
    )

    with app.app_context():
        msg = db.session.get(Message, mid)
        msg.timestamp = datetime.utcnow() - timedelta(days=2)
        db.session.commit()

    clean_expired_messages()

    with app.app_context():
        assert db.session.get(Message, mid) is None
