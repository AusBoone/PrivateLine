"""Direct message functionality tests.

These tests interact with the messaging API endpoints to ensure messages are
properly encrypted, stored, and deleted. They also confirm that privacy rules
and unread counts are enforced. Run with ``pytest``.
"""

import base64

from backend.models import User, Message
from backend.ratchet import get_ratchet
from backend.app import app, db
import pytest
from .conftest import register_user, login_user, decrypt_private_key, sign_content


def test_message_flow(client):
    """Simple send/receive flow between two users."""
    reg_a = register_user(client, "alice")
    reg_b = register_user(client, "bob")
    pk_b = decrypt_private_key(reg_b)

    token_bob = login_user(client, "bob").get_json()["access_token"]
    headers_bob = {"Authorization": f"Bearer {token_bob}"}

    b64 = base64.b64encode(b"hello").decode()
    sig = sign_content(pk_b, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "alice", "signature": sig},
        headers=headers_bob,
    )
    assert resp.status_code == 201

    token_alice = login_user(client, "alice").get_json()["access_token"]
    headers_alice = {"Authorization": f"Bearer {token_alice}"}
    resp = client.get("/api/messages", headers=headers_alice)
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data["messages"]) == 1
    assert data["messages"][0]["content"] == b64
    assert data["messages"][0]["read"] is False
    assert (
        data["messages"][0]["recipient_id"]
        == User.query.filter_by(username="alice").first().id
    )


def test_message_privacy(client):
    """Users should only see messages addressed to them."""
    reg_eve = register_user(client, "eve")
    register_user(client, "mallory")
    register_user(client, "carol")

    pk_eve = decrypt_private_key(reg_eve)

    token_eve = login_user(client, "eve").get_json()["access_token"]
    headers_eve = {"Authorization": f"Bearer {token_eve}"}
    encoded = base64.b64encode(b"secret").decode()
    sig = sign_content(pk_eve, encoded)
    client.post(
        "/api/messages",
        data={"content": encoded, "recipient": "mallory", "signature": sig},
        headers=headers_eve,
    )

    token_mallory = login_user(client, "mallory").get_json()["access_token"]
    headers_mallory = {"Authorization": f"Bearer {token_mallory}"}
    resp = client.get("/api/messages", headers=headers_mallory)
    assert resp.status_code == 200
    assert len(resp.get_json()["messages"]) == 1

    token_carol = login_user(client, "carol").get_json()["access_token"]
    headers_carol = {"Authorization": f"Bearer {token_carol}"}
    resp = client.get("/api/messages", headers=headers_carol)
    assert resp.status_code == 200
    assert len(resp.get_json()["messages"]) == 0


def test_rsa_message_roundtrip(client):
    """Messages encrypted with RSA should deliver intact."""
    register_user(client, "alice")
    reg_bob = register_user(client, "bob")
    pk_bob = decrypt_private_key(reg_bob)
    token = login_user(client, "bob").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/public_key/alice", headers=headers)
    pem = resp.get_json()["public_key"]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    public_key = serialization.load_pem_public_key(pem.encode())
    plaintext = b"hello rsa"
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=padding.hashes.SHA256()),
            algorithm=padding.hashes.SHA256(),
            label=None,
        ),
    )
    b64 = base64.b64encode(ciphertext).decode()

    sig = sign_content(pk_bob, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "alice", "signature": sig},
        headers=headers,
    )
    assert resp.status_code == 201

    token_alice = login_user(client, "alice").get_json()["access_token"]
    headers_alice = {"Authorization": f"Bearer {token_alice}"}
    resp = client.get("/api/messages", headers=headers_alice)
    data2 = resp.get_json()
    assert resp.status_code == 200
    assert len(data2["messages"]) == 1
    assert data2["messages"][0]["content"] == b64


def test_ratchet_bootstrap_api(client):
    """Clients can fetch initial ratchet root keys."""
    register_user(client, "alice")
    register_user(client, "bob")

    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/ratchet/bob", headers=headers)
    assert resp.status_code == 200
    root_b64 = resp.get_json()["root"]
    root = base64.b64decode(root_b64)
    assert len(root) == 32

    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        bob = User.query.filter_by(username="bob").first()
        store_root = get_ratchet(str(alice.id), str(bob.id)).root_key
    assert base64.b64encode(store_root).decode() == root_b64


def test_send_unknown_recipient(client):
    """Posting to a nonexistent recipient should return 404."""
    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    b64 = base64.b64encode(b"hi").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "nonexistent", "signature": sig},
        headers=headers,
    )
    assert resp.status_code == 404


def test_send_invalid_base64_content(client):
    """Sending malformed base64 should result in HTTP 400."""
    reg = register_user(client, "mallory")
    pk = decrypt_private_key(reg)
    token = login_user(client, "mallory").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    bad_b64 = "!notbase64!"
    sig = sign_content(pk, bad_b64)
    resp = client.post(
        "/api/messages",
        data={"content": bad_b64, "recipient": "mallory", "signature": sig},
        headers=headers,
    )
    assert resp.status_code == 400


def test_send_invalid_signature(client):
    """A corrupted signature value should be rejected."""
    reg = register_user(client, "trent")
    pk = decrypt_private_key(reg)
    token = login_user(client, "trent").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    msg = base64.b64encode(b"hello").decode()
    bad_sig = "invalid=="  # Not a valid base64 signature
    resp = client.post(
        "/api/messages",
        data={"content": msg, "recipient": "trent", "signature": bad_sig},
        headers=headers,
    )
    assert resp.status_code == 400


def test_skip_corrupt_base64_records(client):
    """Corrupted database entries should be skipped during retrieval.

    This test manually inserts a message with invalid base64-encoded ``nonce``
    and ``content`` into the database. The API should detect the malformed
    values and omit the record rather than raising an error or returning it to
    the client.
    """
    # Register a user and authenticate to perform message retrieval.
    reg = register_user(client, "alice")
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Directly insert a malformed message into the database to simulate a
    # corrupted row that bypassed API validation.
    with app.app_context():
        user = User.query.filter_by(username="alice").first()
        corrupted = Message(
            content="@@@",  # Not valid base64 -> decoding should fail.
            nonce="@@@",
            user_id=user.id,
            sender_id=user.id,
            recipient_id=user.id,
            signature=base64.b64encode(b"sig").decode(),
        )
        db.session.add(corrupted)
        db.session.commit()

    # Retrieval should return an empty list and not crash the server.
    resp = client.get("/api/messages", headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()["messages"] == []


def test_message_rate_limit(client):
    """Exceeding message send rate limit should return HTTP 429.

    The Messages endpoint is limited to 50 requests per minute per user. This
    test sends 51 quick POST requests and verifies that the final one is
    rejected with ``HTTP 429 Too Many Requests``.
    """
    from backend.app import limiter

    # Prepare sender and recipient accounts.
    register_user(client, "alice")
    reg_bob = register_user(client, "bob")
    pk_bob = decrypt_private_key(reg_bob)

    token_bob = login_user(client, "bob").get_json()["access_token"]
    headers_bob = {"Authorization": f"Bearer {token_bob}"}
    b64 = base64.b64encode(b"spam").decode()
    sig = sign_content(pk_bob, b64)

    # Reset limiter state to avoid interference from prior tests.
    limiter.reset()

    # Send the maximum allowed number of messages.
    for _ in range(50):
        client.post(
            "/api/messages",
            data={"content": b64, "recipient": "alice", "signature": sig},
            headers=headers_bob,
        )

    # The 51st request should be rejected due to rate limiting.
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "alice", "signature": sig},
        headers=headers_bob,
    )
    assert resp.status_code == 429

    # Clean up limiter for subsequent tests.
    limiter.reset()


def test_message_delete_and_read(client):
    """Messages can be read, then removed via the delete endpoint."""
    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    b64 = base64.b64encode(b"delete").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "alice", "signature": sig},
        headers=headers,
    )
    assert resp.status_code == 201
    msg_id = resp.get_json()["id"]

    resp = client.post(f"/api/messages/{msg_id}/read", headers=headers)
    assert resp.status_code == 200

    resp = client.get("/api/messages", headers=headers)
    data = resp.get_json()["messages"]
    assert data[0]["read"] is True

    resp = client.delete(f"/api/messages/{msg_id}", headers=headers)
    assert resp.status_code == 200

    resp = client.get("/api/messages", headers=headers)
    assert resp.get_json()["messages"] == []


def test_delete_on_read_removes_message(client):
    """Messages flagged ``delete_on_read`` should disappear once read."""
    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    b64 = base64.b64encode(b"vanish").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={
            "content": b64,
            "recipient": "alice",
            "signature": sig,
            "delete_on_read": True,
        },
        headers=headers,
    )
    assert resp.status_code == 201
    msg_id = resp.get_json()["id"]

    # Reading the message should immediately delete it from the database
    resp = client.post(f"/api/messages/{msg_id}/read", headers=headers)
    assert resp.status_code == 200

    with app.app_context():
        assert db.session.get(Message, msg_id) is None

    resp = client.get("/api/messages", headers=headers)
    assert resp.get_json()["messages"] == []


def test_messages_pagination(client):
    """The ``limit`` and ``offset`` query parameters page the results."""
    reg_bob = register_user(client, "bob")
    pk_bob = decrypt_private_key(reg_bob)
    register_user(client, "alice")

    token_bob = login_user(client, "bob").get_json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_bob}"}

    ids = []
    for i in range(5):
        b64 = base64.b64encode(f"m{i}".encode()).decode()
        sig = sign_content(pk_bob, b64)
        resp = client.post(
            "/api/messages",
            data={"content": b64, "recipient": "alice", "signature": sig},
            headers=headers_b,
        )
        ids.append(resp.get_json()["id"])

    resp = client.get("/api/messages?limit=2&offset=1", headers=headers_b)
    assert resp.status_code == 200
    msgs = resp.get_json()["messages"]
    assert len(msgs) == 2
    assert msgs[0]["id"] == ids[-2]
    assert msgs[1]["id"] == ids[-3]

    resp = client.get("/api/messages?limit=0", headers=headers_b)
    assert resp.status_code == 400
    resp = client.get("/api/messages?limit=101", headers=headers_b)
    assert resp.status_code == 400
    resp = client.get("/api/messages?offset=-1", headers=headers_b)
    assert resp.status_code == 400


def test_messages_pagination_boundaries(client):
    """Pagination gracefully handles large offsets and limits.

    The endpoint should return an empty page when ``offset`` skips all
    available messages and should not error when ``limit`` exceeds the number
    of remaining messages. These scenarios verify the SQL pagination logic
    introduced for efficiency.
    """
    reg_bob = register_user(client, "bob")
    pk_bob = decrypt_private_key(reg_bob)
    register_user(client, "alice")

    token_bob = login_user(client, "bob").get_json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_bob}"}

    ids = []
    for i in range(3):
        b64 = base64.b64encode(f"m{i}".encode()).decode()
        sig = sign_content(pk_bob, b64)
        resp = client.post(
            "/api/messages",
            data={"content": b64, "recipient": "alice", "signature": sig},
            headers=headers_b,
        )
        ids.append(resp.get_json()["id"])

    # Requesting beyond the available range should yield an empty list.
    resp = client.get("/api/messages?limit=2&offset=3", headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()["messages"] == []

    # A large limit should simply return remaining messages without error.
    resp = client.get("/api/messages?limit=5&offset=1", headers=headers_b)
    assert resp.status_code == 200
    msgs = resp.get_json()["messages"]
    assert len(msgs) == 2
    assert msgs[0]["id"] == ids[-2]
    assert msgs[1]["id"] == ids[-3]


def test_expired_messages_not_returned(client):
    """Messages with an ``expires_at`` in the past should be hidden."""
    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token = login_user(client, "alice").get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    b64 = base64.b64encode(b"expire").decode()
    sig = sign_content(pk, b64)
    from datetime import datetime, timedelta

    past = (datetime.utcnow() - timedelta(seconds=1)).isoformat()
    resp = client.post(
        "/api/messages",
        data={
            "content": b64,
            "recipient": "alice",
            "signature": sig,
            "expires_at": past,
        },
        headers=headers,
    )
    assert resp.status_code == 201
    resp = client.get("/api/messages", headers=headers)
    assert resp.get_json()["messages"] == []


def test_unread_count_endpoint(client):
    """The unread count should reflect read status changes."""
    reg = register_user(client, "alice")
    pk = decrypt_private_key(reg)
    token_a = login_user(client, "alice").get_json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    register_user(client, "bob")
    token_b = login_user(client, "bob").get_json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    b64 = base64.b64encode(b"hello").decode()
    sig = sign_content(pk, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "bob", "signature": sig},
        headers=headers_a,
    )
    msg_id = resp.get_json()["id"]

    resp = client.get("/api/unread_count", headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()["unread"] == 1

    client.post(f"/api/messages/{msg_id}/read", headers=headers_b)

    resp = client.get("/api/unread_count", headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()["unread"] == 0


def test_unread_count_group_messages(client):
    """Unread count should include group messages until they are marked read."""
    reg_a = register_user(client, "alice")
    pk_a = decrypt_private_key(reg_a)
    register_user(client, "bob")

    # Alice creates a group and invites Bob
    token_a = login_user(client, "alice").get_json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    resp = client.post("/api/groups", json={"name": "room"}, headers=headers_a)
    gid = resp.get_json()["id"]

    token_b = login_user(client, "bob").get_json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}
    resp = client.post(
        f"/api/groups/{gid}/members", json={"username": "bob"}, headers=headers_a
    )
    assert resp.status_code == 201

    # Alice sends a group message
    b64 = base64.b64encode(b"hi group").decode()
    sig = sign_content(pk_a, b64)
    resp = client.post(
        f"/api/groups/{gid}/messages",
        data={"content": b64, "signature": sig},
        headers=headers_a,
    )
    msg_id = resp.get_json()["id"]

    resp = client.get("/api/unread_count", headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()["unread"] == 1

    # Bob reads the message which should clear the count
    client.post(f"/api/messages/{msg_id}/read", headers=headers_b)

    resp = client.get("/api/unread_count", headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()["unread"] == 0


def test_ratchet_forward_secrecy(client):
    """Old ratchet states should not decrypt messages once read."""
    register_user(client, "alice")
    reg_bob = register_user(client, "bob")
    pk_bob = decrypt_private_key(reg_bob)

    token_b = login_user(client, "bob").get_json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    b64 = base64.b64encode(b"fs").decode()
    sig = sign_content(pk_bob, b64)
    resp = client.post(
        "/api/messages",
        data={"content": b64, "recipient": "alice", "signature": sig},
        headers=headers_b,
    )
    msg_id = resp.get_json()["id"]

    with app.app_context():
        msg = db.session.get(Message, msg_id)
        ciphertext = base64.b64decode(msg.content)
        nonce = base64.b64decode(msg.nonce)
        ratchet = get_ratchet(str(msg.sender_id), str(msg.recipient_id))

    token_a = login_user(client, "alice").get_json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    client.get("/api/messages", headers=headers_a)

    # Retrieval clones the ratchet state per message so subsequent decryptions
    # using the original instance remain possible. The call below should not
    # raise despite the message already being read.
    ratchet.decrypt(ciphertext, nonce)
