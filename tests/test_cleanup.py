"""Regression tests for the periodic message cleanup routine.

These tests exercise the edge cases for :func:`clean_expired_messages`,
including expired timestamps, user and conversation retention rules and the
overall transaction behavior.  The intent is to ensure that the set-based SQL
implementation continues to behave correctly as the code evolves.
"""

from datetime import datetime, timedelta
import base64
import io
import pytest
from werkzeug.datastructures import FileStorage

from backend.app import app, clean_expired_messages, db
from backend.models import File, Message
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


def test_conversation_retention_override(client):
    """Conversation-specific retention should override the user default."""
    register_user(client, "alice")
    reg_bob = register_user(client, "bob")
    pk_bob = decrypt_private_key(reg_bob)

    token_b = login_user(client, "bob").get_json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    token_a = login_user(client, "alice").get_json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Bob sends a message to Alice and she reads it
    b64 = base64.b64encode(b"hi").decode()
    sig = sign_content(pk_bob, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "alice", "signature": sig},
        headers=headers_b,
    )
    mid = resp.get_json()["id"]
    client.post(f"/api/messages/{mid}/read", headers=headers_a)

    # Set conversation retention between Alice and Bob to 1 day
    client.put(
        "/api/conversations/bob/retention",
        json={"retention_days": 1},
        headers=headers_a,
    )

    with app.app_context():
        msg = db.session.get(Message, mid)
        msg.timestamp = datetime.utcnow() - timedelta(days=2)
        db.session.commit()

    clean_expired_messages()

    with app.app_context():
        assert db.session.get(Message, mid) is None


def test_conversation_longer_retention(client):
    """A longer conversation TTL preserves messages beyond the user default."""
    reg_a = register_user(client, "alice")
    pk_a = decrypt_private_key(reg_a)
    register_user(client, "bob")

    token_a = login_user(client, "alice").get_json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    token_b = login_user(client, "bob").get_json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    b64 = base64.b64encode(b"persist").decode()
    sig = sign_content(pk_a, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "bob", "signature": sig},
        headers=headers_a,
    )
    mid = resp.get_json()["id"]
    client.post(f"/api/messages/{mid}/read", headers=headers_b)

    # User default 1 day but conversation set to 10 days
    client.put(
        "/api/account-settings",
        json={"messageRetentionDays": 1},
        headers=headers_b,
    )
    client.put(
        "/api/conversations/alice/retention",
        json={"retention_days": 10},
        headers=headers_b,
    )

    with app.app_context():
        msg = db.session.get(Message, mid)
        msg.timestamp = datetime.utcnow() - timedelta(days=2)
        db.session.commit()

    clean_expired_messages()

    with app.app_context():
        assert db.session.get(Message, mid) is not None


def test_cleanup_commits_once(monkeypatch, client):
    """Cleanup should commit a single transaction even for many deletions.

    The refactored cleanup uses set-based statements and must therefore only
    call ``db.session.commit`` once regardless of how many messages qualify for
    removal. This test patches ``commit`` to count invocations and ensures that
    multiple deletions still result in a single commit.
    """

    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    payload = base64.b64encode(b"tmp").decode()
    sig = sign_content(pk, payload)

    # One message expires explicitly, another relies on retention policy
    past = (datetime.utcnow() - timedelta(days=2)).isoformat()
    resp1 = client.post(
        "/api/messages",
        data={"content": payload, "recipient": "alice", "signature": sig, "expires_at": past},
        headers=headers,
    )
    resp2 = client.post(
        "/api/messages",
        data={"content": payload, "recipient": "alice", "signature": sig},
        headers=headers,
    )
    mid2 = resp2.get_json()["id"]
    client.post(f"/api/messages/{mid2}/read", headers=headers)

    # Retain read messages for only one day
    client.put(
        "/api/account-settings",
        json={"messageRetentionDays": 1},
        headers=headers,
    )
    with app.app_context():
        msg = db.session.get(Message, mid2)
        msg.timestamp = datetime.utcnow() - timedelta(days=2)
        db.session.commit()

    commits = {"count": 0}
    original_commit = db.session.commit

    def counting_commit():
        commits["count"] += 1
        original_commit()

    monkeypatch.setattr(db.session, "commit", counting_commit)

    clean_expired_messages()

    with app.app_context():
        assert commits["count"] == 1
        assert Message.query.count() == 0


def test_cleanup_rolls_back_on_error(monkeypatch, client):
    """Message and file deletions should roll back together on exceptions.

    This test simulates an error during ``clean_expired_messages`` by forcing
    :func:`remove_orphan_files` to raise. The nested transaction introduced in
    2035 must ensure that both message and file records remain intact and
    properly linked so no orphaned file rows persist after the failure.
    """

    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Upload a small file and send a message referencing it.
    fs = FileStorage(stream=io.BytesIO(b"data"), filename="tmp.txt")
    resp = client.post(
        "/api/files",
        data={"file": fs},
        headers=headers,
        content_type="multipart/form-data",
    )
    fid = resp.get_json()["file_id"]

    msg_b64 = base64.b64encode(b"hi").decode()
    sig = sign_content(pk, msg_b64)
    resp = client.post(
        "/api/messages",
        data={
            "content": msg_b64,
            "recipient": "alice",
            "file_id": fid,
            "signature": sig,
        },
        headers=headers,
    )
    mid = resp.get_json()["id"]
    client.post(f"/api/messages/{mid}/read", headers=headers)

    # Set retention to one day then backdate the message so it qualifies for
    # cleanup.
    client.put(
        "/api/account-settings",
        json={"messageRetentionDays": 1},
        headers=headers,
    )
    with app.app_context():
        msg = db.session.get(Message, mid)
        msg.timestamp = datetime.utcnow() - timedelta(days=2)
        db.session.commit()

    # Force remove_orphan_files to raise, simulating a failure during cleanup.
    def boom(*args, **kwargs):  # noqa: D401 - small helper
        raise RuntimeError("boom")

    monkeypatch.setattr("backend.resources.remove_orphan_files", boom)

    with pytest.raises(RuntimeError):
        clean_expired_messages()

    with app.app_context():
        # Reset session state after the raised exception before querying.
        db.session.rollback()
        # Neither message nor file should have been deleted and the relationship
        # should be intact, proving that no orphan files remain.
        assert db.session.get(Message, mid) is not None
        assert db.session.get(File, fid) is not None
        assert db.session.get(Message, mid).file_id == fid
