"""Direct message functionality tests."""
import base64

from backend.models import User
from .conftest import register_user, login_user, decrypt_private_key, sign_content


def test_message_flow(client):
    reg_a = register_user(client, 'alice')
    reg_b = register_user(client, 'bob')
    pk_b = decrypt_private_key(reg_b)

    token_bob = login_user(client, 'bob').get_json()['access_token']
    headers_bob = {'Authorization': f'Bearer {token_bob}'}

    b64 = base64.b64encode(b'hello').decode()
    sig = sign_content(pk_b, b64)
    resp = client.post('/api/messages', data={'content': b64, 'recipient': 'alice', 'signature': sig}, headers=headers_bob)
    assert resp.status_code == 201

    resp = client.get('/api/messages', headers=headers_bob)
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data['messages']) == 1
    assert data['messages'][0]['content'] == b64
    assert data['messages'][0]['read'] is False
    assert data['messages'][0]['recipient_id'] == User.query.filter_by(username='alice').first().id

    token_alice = login_user(client, 'alice').get_json()['access_token']
    headers_alice = {'Authorization': f'Bearer {token_alice}'}
    resp = client.get('/api/messages', headers=headers_alice)
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data['messages']) == 1
    assert data['messages'][0]['content'] == b64
    assert data['messages'][0]['read'] is False


def test_message_privacy(client):
    reg_eve = register_user(client, 'eve')
    register_user(client, 'mallory')
    register_user(client, 'carol')

    pk_eve = decrypt_private_key(reg_eve)

    token_eve = login_user(client, 'eve').get_json()['access_token']
    headers_eve = {'Authorization': f'Bearer {token_eve}'}
    encoded = base64.b64encode(b'secret').decode()
    sig = sign_content(pk_eve, encoded)
    client.post('/api/messages', data={'content': encoded, 'recipient': 'mallory', 'signature': sig}, headers=headers_eve)

    token_mallory = login_user(client, 'mallory').get_json()['access_token']
    headers_mallory = {'Authorization': f'Bearer {token_mallory}'}
    resp = client.get('/api/messages', headers=headers_mallory)
    assert resp.status_code == 200
    assert len(resp.get_json()['messages']) == 1

    token_carol = login_user(client, 'carol').get_json()['access_token']
    headers_carol = {'Authorization': f'Bearer {token_carol}'}
    resp = client.get('/api/messages', headers=headers_carol)
    assert resp.status_code == 200
    assert len(resp.get_json()['messages']) == 0


def test_rsa_message_roundtrip(client):
    register_user(client, 'alice')
    reg_bob = register_user(client, 'bob')
    pk_bob = decrypt_private_key(reg_bob)
    token = login_user(client, 'bob').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    resp = client.get('/api/public_key/alice', headers=headers)
    pem = resp.get_json()['public_key']
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    public_key = serialization.load_pem_public_key(pem.encode())
    plaintext = b'hello rsa'
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
    resp = client.post('/api/messages', data={'content': b64, 'recipient': 'alice', 'signature': sig}, headers=headers)
    assert resp.status_code == 201

    resp = client.get('/api/messages', headers=headers)
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data['messages']) == 1
    assert data['messages'][0]['content'] == b64
    assert data['messages'][0]['read'] is False

    token_alice = login_user(client, 'alice').get_json()['access_token']
    headers_alice = {'Authorization': f'Bearer {token_alice}'}
    resp = client.get('/api/messages', headers=headers_alice)
    data2 = resp.get_json()
    assert resp.status_code == 200
    assert len(data2['messages']) == 1
    assert data2['messages'][0]['content'] == b64


def test_send_unknown_recipient(client):
    reg = register_user(client, 'alice')
    pk = decrypt_private_key(reg)
    token = login_user(client, 'alice').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    b64 = base64.b64encode(b'hi').decode()
    sig = sign_content(pk, b64)
    resp = client.post('/api/messages', data={'content': b64, 'recipient': 'nonexistent', 'signature': sig}, headers=headers)
    assert resp.status_code == 404


def test_message_delete_and_read(client):
    reg = register_user(client, 'alice')
    pk = decrypt_private_key(reg)
    token = login_user(client, 'alice').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}
    b64 = base64.b64encode(b'delete').decode()
    sig = sign_content(pk, b64)
    resp = client.post('/api/messages', data={'content': b64, 'recipient': 'alice', 'signature': sig}, headers=headers)
    assert resp.status_code == 201
    msg_id = resp.get_json()['id']

    resp = client.post(f'/api/messages/{msg_id}/read', headers=headers)
    assert resp.status_code == 200

    resp = client.get('/api/messages', headers=headers)
    data = resp.get_json()['messages']
    assert data[0]['read'] is True

    resp = client.delete(f'/api/messages/{msg_id}', headers=headers)
    assert resp.status_code == 200

    resp = client.get('/api/messages', headers=headers)
    assert resp.get_json()['messages'] == []


def test_messages_pagination(client):
    reg_bob = register_user(client, 'bob')
    pk_bob = decrypt_private_key(reg_bob)
    register_user(client, 'alice')

    token_bob = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_bob}'}

    ids = []
    for i in range(5):
        b64 = base64.b64encode(f'm{i}'.encode()).decode()
        sig = sign_content(pk_bob, b64)
        resp = client.post('/api/messages', data={'content': b64, 'recipient': 'alice', 'signature': sig}, headers=headers_b)
        ids.append(resp.get_json()['id'])

    resp = client.get('/api/messages?limit=2&offset=1', headers=headers_b)
    assert resp.status_code == 200
    msgs = resp.get_json()['messages']
    assert len(msgs) == 2
    assert msgs[0]['id'] == ids[-2]
    assert msgs[1]['id'] == ids[-3]

    resp = client.get('/api/messages?limit=0', headers=headers_b)
    assert resp.status_code == 400
    resp = client.get('/api/messages?limit=101', headers=headers_b)
    assert resp.status_code == 400
    resp = client.get('/api/messages?offset=-1', headers=headers_b)
    assert resp.status_code == 400


def test_expired_messages_not_returned(client):
    """Messages with an ``expires_at`` in the past should be hidden."""
    reg = register_user(client, 'alice')
    pk = decrypt_private_key(reg)
    token = login_user(client, 'alice').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}
    b64 = base64.b64encode(b'expire').decode()
    sig = sign_content(pk, b64)
    from datetime import datetime, timedelta
    past = (datetime.utcnow() - timedelta(seconds=1)).isoformat()
    resp = client.post(
        '/api/messages',
        data={'content': b64, 'recipient': 'alice', 'signature': sig, 'expires_at': past},
        headers=headers,
    )
    assert resp.status_code == 201
    resp = client.get('/api/messages', headers=headers)
    assert resp.get_json()['messages'] == []


def test_unread_count_endpoint(client):
    """The unread count should reflect read status changes."""
    reg = register_user(client, 'alice')
    pk = decrypt_private_key(reg)
    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}

    register_user(client, 'bob')
    token_b = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}

    b64 = base64.b64encode(b'hello').decode()
    sig = sign_content(pk, b64)
    resp = client.post('/api/messages', data={'content': b64, 'recipient': 'bob', 'signature': sig}, headers=headers_a)
    msg_id = resp.get_json()['id']

    resp = client.get('/api/unread_count', headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()['unread'] == 1

    client.post(f'/api/messages/{msg_id}/read', headers=headers_b)

    resp = client.get('/api/unread_count', headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()['unread'] == 0


def test_unread_count_group_messages(client):
    """Unread count should include group messages until they are marked read."""
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')

    # Alice creates a group and invites Bob
    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'room'}, headers=headers_a)
    gid = resp.get_json()['id']

    token_b = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}
    resp = client.post(
        f'/api/groups/{gid}/members', json={'username': 'bob'}, headers=headers_a
    )
    assert resp.status_code == 201

    # Alice sends a group message
    b64 = base64.b64encode(b'hi group').decode()
    sig = sign_content(pk_a, b64)
    resp = client.post(
        f'/api/groups/{gid}/messages',
        data={'content': b64, 'signature': sig},
        headers=headers_a,
    )
    msg_id = resp.get_json()['id']

    resp = client.get('/api/unread_count', headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()['unread'] == 1

    # Bob reads the message which should clear the count
    client.post(f'/api/messages/{msg_id}/read', headers=headers_b)

    resp = client.get('/api/unread_count', headers=headers_b)
    assert resp.status_code == 200
    assert resp.get_json()['unread'] == 0
