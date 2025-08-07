"""Group chat integration tests.

These tests exercise group messaging features including member management,
message retention policies, and access control rules. Each test simulates
realistic user interactions to verify that the API enforces permissions and
cleans up state correctly.

Update: expanded coverage to validate group-specific retention cleanup.
"""

import base64
from datetime import datetime, timedelta

from backend.app import app, clean_expired_messages, db
from backend.models import Group, Message, User
from .conftest import (
    decrypt_private_key,
    login_user,
    register_user,
    sign_content,
)


def test_group_message_flow(client):
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')

    token_alice = login_user(client, 'alice').get_json()['access_token']
    headers_alice = {'Authorization': f'Bearer {token_alice}'}
    resp = client.post('/api/groups', json={'name': 'demo'}, headers=headers_alice)
    gid = resp.get_json()['id']

    token_bob = login_user(client, 'bob').get_json()['access_token']
    headers_bob = {'Authorization': f'Bearer {token_bob}'}
    resp = client.post(f'/api/groups/{gid}/members', json={'username': 'bob'}, headers=headers_alice)
    assert resp.status_code == 201

    b64 = base64.b64encode(b'hi').decode()
    sig = sign_content(pk_a, b64)
    resp = client.post(f'/api/groups/{gid}/messages', data={'content': b64, 'signature': sig}, headers=headers_alice)
    assert resp.status_code == 201

    resp = client.get(f'/api/groups/{gid}/messages', headers=headers_bob)
    assert resp.status_code == 200
    msgs = resp.get_json()['messages']
    assert len(msgs) == 1


def test_group_message_too_long(client):
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')

    token_alice = login_user(client, 'alice').get_json()['access_token']
    headers_alice = {'Authorization': f'Bearer {token_alice}'}
    resp = client.post('/api/groups', json={'name': 'long'}, headers=headers_alice)
    gid = resp.get_json()['id']
    client.post(f'/api/groups/{gid}/members', json={'username': 'bob'}, headers=headers_alice)

    long_content = base64.b64encode(b'A' * 1501).decode()
    sig = sign_content(pk_a, long_content)
    resp = client.post(f'/api/groups/{gid}/messages', data={'content': long_content, 'signature': sig}, headers=headers_alice)
    assert resp.status_code == 400


def test_group_key_distribution(client):
    register_user(client, 'alice')
    register_user(client, 'bob')
    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'g1'}, headers=headers_a)
    gid = resp.get_json()['id']
    resp = client.post(f'/api/groups/{gid}/members', json={'username': 'bob'}, headers=headers_a)
    assert resp.status_code == 201
    with app.app_context():
        key_before = db.session.get(Group, gid).aes_key

    token_b = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}
    resp = client.get(f'/api/groups/{gid}/key', headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()['key'] == key_before

    resp = client.put(f'/api/groups/{gid}/key', headers=headers_a)
    assert resp.status_code == 200
    new_key = resp.get_json()['key']
    assert new_key != key_before


def test_group_message_read_requires_membership(client):
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')
    register_user(client, 'carol')

    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'grp'}, headers=headers_a)
    gid = resp.get_json()['id']
    resp = client.post(f'/api/groups/{gid}/members', json={'username': 'bob'}, headers=headers_a)
    assert resp.status_code == 201
    with app.app_context():
        bob_id = User.query.filter_by(username='bob').first().id

    b64 = base64.b64encode(b'hey').decode()
    sig = sign_content(pk_a, b64)
    resp = client.post(f'/api/groups/{gid}/messages', data={'content': b64, 'signature': sig}, headers=headers_a)
    assert resp.status_code == 201
    msg_id = resp.get_json()['id']

    token_carol = login_user(client, 'carol').get_json()['access_token']
    headers_c = {'Authorization': f'Bearer {token_carol}'}
    resp = client.post(f'/api/messages/{msg_id}/read', headers=headers_c)
    assert resp.status_code == 403


def test_group_message_id_usage(client):
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')

    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'room'}, headers=headers_a)
    gid = resp.get_json()['id']

    token_b = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}
    resp = client.post(f'/api/groups/{gid}/members', json={'username': 'bob'}, headers=headers_a)
    assert resp.status_code == 201
    with app.app_context():
        bob_id = User.query.filter_by(username='bob').first().id

    b64 = base64.b64encode(b'hello').decode()
    sig = sign_content(pk_a, b64)
    resp = client.post(f'/api/groups/{gid}/messages', data={'content': b64, 'signature': sig}, headers=headers_a)
    assert resp.status_code == 201
    mid = resp.get_json()['id']

    resp = client.post(f'/api/messages/{mid}/read', headers=headers_b)
    assert resp.status_code == 200
    resp = client.get(f'/api/groups/{gid}/messages', headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()['messages'][0]['read'] is True

    resp = client.delete(f'/api/messages/{mid}', headers=headers_a)
    assert resp.status_code == 200
    resp = client.get(f'/api/groups/{gid}/messages', headers=headers_a)
    assert resp.get_json()['messages'] == []


def test_group_member_invite_and_leave(client):
    register_user(client, 'alice')
    register_user(client, 'bob')

    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'leave'}, headers=headers_a)
    gid = resp.get_json()['id']

    resp = client.post(f'/api/groups/{gid}/members', json={'username': 'bob'}, headers=headers_a)
    assert resp.status_code == 201

    token_b = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}
    with app.app_context():
        bob_id = User.query.filter_by(username='bob').first().id

    resp = client.delete(f'/api/groups/{gid}/members/{bob_id}', headers=headers_b)
    assert resp.status_code == 200
    resp = client.get(f'/api/groups/{gid}/messages', headers=headers_b)
    assert resp.status_code == 403


def test_group_messages_pagination(client):
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')

    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'pag'}, headers=headers_a)
    gid = resp.get_json()['id']
    token_b = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}
    client.post(f'/api/groups/{gid}/members', json={'username': 'bob'}, headers=headers_a)

    ids = []
    for i in range(4):
        b64 = base64.b64encode(f'g{i}'.encode()).decode()
        sig = sign_content(pk_a, b64)
        resp = client.post(f'/api/groups/{gid}/messages', data={'content': b64, 'signature': sig}, headers=headers_a)
        ids.append(resp.get_json()['id'])

    resp = client.get(f'/api/groups/{gid}/messages?limit=2&offset=1', headers=headers_b)
    assert resp.status_code == 200
    msgs = resp.get_json()['messages']
    assert len(msgs) == 2
    assert msgs[0]['id'] == ids[-2]
    assert msgs[1]['id'] == ids[-3]

    resp = client.get(f'/api/groups/{gid}/messages?limit=0', headers=headers_b)
    assert resp.status_code == 400
    resp = client.get(f'/api/groups/{gid}/messages?limit=101', headers=headers_b)
    assert resp.status_code == 400
    resp = client.get(f'/api/groups/{gid}/messages?offset=-1', headers=headers_b)
    assert resp.status_code == 400


def test_group_retention_cleanup(client):
    """Old read messages respect group-specific retention policies."""

    # Register two users and create a shared group where retention is tested.
    reg_a = register_user(client, "alice")
    pk_a = decrypt_private_key(reg_a)
    register_user(client, "bob")

    token_a = login_user(client, "alice").get_json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}
    resp = client.post("/api/groups", json={"name": "ttl"}, headers=headers_a)
    gid = resp.get_json()["id"]

    token_b = login_user(client, "bob").get_json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}
    client.post(
        f"/api/groups/{gid}/members", json={"username": "bob"}, headers=headers_a
    )

    # Alice sends a message that Bob reads, marking it as eligible for retention.
    b64 = base64.b64encode(b"old").decode()
    sig = sign_content(pk_a, b64)
    resp = client.post(
        f"/api/groups/{gid}/messages",
        data={"content": b64, "signature": sig},
        headers=headers_a,
    )
    mid = resp.get_json()["id"]

    # Reading the message toggles the ``read`` flag so retention applies.
    resp = client.post(f"/api/messages/{mid}/read", headers=headers_b)
    assert resp.status_code == 200

    # Configure a one-day retention period for the group.
    resp = client.put(
        f"/api/groups/{gid}/retention",
        json={"retention_days": 1},
        headers=headers_a,
    )
    assert resp.status_code == 200

    # Manipulate timestamp to simulate an old message past the retention.
    with app.app_context():
        msg = db.session.get(Message, mid)
        msg.timestamp = datetime.utcnow() - timedelta(days=2)
        db.session.commit()

    # Cleanup should remove the message now that it exceeds the TTL.
    clean_expired_messages()

    with app.app_context():
        assert db.session.get(Message, mid) is None


def test_message_endpoint_group_membership_required(client):
    register_user(client, 'alice')
    reg_bob = register_user(client, 'bob')
    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'memb'}, headers=headers_a)
    gid = resp.get_json()['id']
    token_b = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}
    b64 = base64.b64encode(b'hi').decode()
    sig = sign_content(decrypt_private_key(reg_bob), b64)
    resp = client.post('/api/messages', data={'content': b64, 'group_id': gid, 'signature': sig}, headers=headers_b)
    assert resp.status_code == 403
