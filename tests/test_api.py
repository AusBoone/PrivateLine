"""Integration tests exercising the PrivateLine REST API."""

import os
import base64
import io
import pytest
from base64 import b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# These imports will fail if Flask and related dependencies are not installed.
# Ensure an AES key is available for the backend before it is imported. Tests
# run without a .env file so we generate a deterministic key on the fly.
# Generate a deterministic AES key for tests so encryption is repeatable
os.environ.setdefault("AES_KEY", base64.b64encode(os.urandom(32)).decode())

from backend.app import app, db, RedisBlocklist
from backend.models import User

@pytest.fixture(autouse=True)
def fake_blocklist(monkeypatch):
    import fakeredis
    bl = RedisBlocklist(fakeredis.FakeRedis())
    monkeypatch.setattr("backend.app.token_blocklist", bl)
    monkeypatch.setattr("backend.resources.token_blocklist", bl)
    yield

@pytest.fixture
def client():
    """Create a test client with an in-memory database."""
    # Use SQLite in-memory DB so each test starts with a clean state
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
    with app.test_client() as client:
        yield client
    with app.app_context():
        db.drop_all()


def register_user(client, username='alice'):
    """Helper to register a user in tests."""
    # Minimal payload required by /api/register
    data = {
        'username': username,
        'email': f'{username}@example.com',
        'password': 'secret',
    }
    return client.post('/api/register', data=data)


def login_user(client, username='alice'):
    """Helper to log in a user and return the response."""
    # Password is fixed as 'secret' for all test users
    return client.post('/api/login', json={
        'username': username,
        'password': 'secret',
    })

def decrypt_private_key(resp):
    """Return a private key object decrypted from the registration response."""
    from cryptography.hazmat.primitives import serialization
    # Extract the encryption parameters returned by /api/register
    data = resp.get_json()
    salt = b64decode(data['salt'])
    nonce = b64decode(data['nonce'])
    ciphertext = b64decode(data['encrypted_private_key'])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend(),
    )
    key = kdf.derive(b'secret')
    pem = AESGCM(key).decrypt(nonce, ciphertext, None)
    return serialization.load_pem_private_key(pem, password=None)

def sign_content(private_key, content):
    """Return a base64 signature of ``content`` using ``private_key``."""
    from cryptography.hazmat.primitives.asymmetric import padding as asympad
    # Sign the UTF-8 encoded payload using RSA-PSS
    sig = private_key.sign(
        content.encode(),
        asympad.PSS(mgf=asympad.MGF1(hashes.SHA256()), salt_length=asympad.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()


def test_register_missing_fields(client):
    resp = client.post('/api/register', data={'username': 'x'})
    assert resp.status_code == 400


def test_login_invalid_credentials(client):
    register_user(client, 'dave')
    resp = client.post('/api/login', json={'username': 'dave', 'password': 'bad'})
    assert resp.status_code == 401


def test_register_duplicate_email(client):
    register_user(client, 'alice')
    resp = client.post(
        '/api/register',
        data={'username': 'bob', 'email': 'alice@example.com', 'password': 'secret'},
    )
    assert resp.status_code == 400


def test_register_and_login(client):
    resp = register_user(client)
    assert resp.status_code == 201
    payload = resp.get_json()
    assert {'encrypted_private_key', 'salt', 'nonce', 'fingerprint'} <= payload.keys()

    # Validate fingerprint matches stored public key
    user = User.query.filter_by(username='alice').first()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import hashlib
    der = user.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    expected_fp = hashlib.sha256(der).hexdigest()
    assert payload['fingerprint'] == expected_fp

    # Attempt to decrypt the private key using the returned parameters
    password = 'secret'.encode()
    salt = b64decode(payload['salt'])
    nonce = b64decode(payload['nonce'])
    ciphertext = b64decode(payload['encrypted_private_key'])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    assert plaintext.startswith(b"-----BEGIN PRIVATE KEY-----")

    resp = login_user(client)
    assert resp.status_code == 200
    assert 'access_token' in resp.get_json()


def test_message_flow(client):
    reg_a = register_user(client, 'alice')
    reg_b = register_user(client, 'bob')
    pk_b = decrypt_private_key(reg_b)

    token_bob = login_user(client, 'bob').get_json()['access_token']
    headers_bob = {'Authorization': f'Bearer {token_bob}'}

    b64 = base64.b64encode(b'hello').decode()
    sig = sign_content(pk_b, b64)
    resp = client.post(
        '/api/messages',
        data={'content': b64, 'recipient': 'alice', 'signature': sig},
        headers=headers_bob,
    )
    assert resp.status_code == 201

    # Sender should see the message
    resp = client.get('/api/messages', headers=headers_bob)
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data['messages']) == 1
    assert data['messages'][0]['content'] == b64
    assert data['messages'][0]['read'] is False
    assert data['messages'][0]['recipient_id'] == User.query.filter_by(username='alice').first().id

    # Recipient should also see the message
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
    client.post(
        '/api/messages',
        data={'content': encoded, 'recipient': 'mallory', 'signature': sig},
        headers=headers_eve,
    )

    token_mallory = login_user(client, 'mallory').get_json()['access_token']
    headers_mallory = {'Authorization': f'Bearer {token_mallory}'}

    # Recipient should see the message
    resp = client.get('/api/messages', headers=headers_mallory)
    assert resp.status_code == 200
    assert len(resp.get_json()['messages']) == 1

    # Third party should not see it
    token_carol = login_user(client, 'carol').get_json()['access_token']
    headers_carol = {'Authorization': f'Bearer {token_carol}'}
    resp = client.get('/api/messages', headers=headers_carol)
    assert resp.status_code == 200
    assert len(resp.get_json()['messages']) == 0


def test_account_settings_update(client):
    register_user(client, 'carol')
    login = login_user(client, 'carol')
    token = login.get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    resp = client.put('/api/account-settings', json={'email': 'carol2@example.com'}, headers=headers)
    assert resp.status_code == 200

    resp = client.put(
        '/api/account-settings',
        json={'currentPassword': 'secret', 'newPassword': 'newsecret'},
        headers=headers,
    )
    assert resp.status_code == 200

    # Login with new password should succeed
    resp = client.post('/api/login', json={'username': 'carol', 'password': 'newsecret'})
    assert resp.status_code == 200


def test_token_refresh(client):
    register_user(client, 'frank')
    token = login_user(client, 'frank').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    resp = client.post('/api/refresh', headers=headers)
    assert resp.status_code == 200
    new_token = resp.get_json()['access_token']
    assert new_token != token

    resp = client.get('/api/messages', headers={'Authorization': f'Bearer {new_token}'})
    assert resp.status_code == 200


def test_token_revocation(client):
    register_user(client, 'gina')
    token = login_user(client, 'gina').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    # revoke the token
    resp = client.post('/api/revoke', headers=headers)
    assert resp.status_code == 200

    # token should no longer authorize requests
    resp = client.get('/api/messages', headers=headers)
    assert resp.status_code == 401

    # a new login should issue a working token
    new_token = login_user(client, 'gina').get_json()['access_token']
    resp = client.get('/api/messages', headers={'Authorization': f'Bearer {new_token}'})
    assert resp.status_code == 200

def test_public_key_endpoint(client):
    register_user(client, 'alice')
    token = login_user(client, 'alice').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    # Query stored PEM directly
    user = User.query.filter_by(username='alice').first()
    resp = client.get('/api/public_key/alice', headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()['public_key'] == user.public_key_pem


def test_rsa_message_roundtrip(client):
    register_user(client, 'alice')
    reg_bob = register_user(client, 'bob')
    pk_bob = decrypt_private_key(reg_bob)
    token = login_user(client, 'bob').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    # fetch alice's public key
    resp = client.get('/api/public_key/alice', headers=headers)
    pem = resp.get_json()['public_key']

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    public_key = serialization.load_pem_public_key(pem.encode())
    plaintext = b'hello rsa'
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    b64 = base64.b64encode(ciphertext).decode()

    sig = sign_content(pk_bob, b64)
    resp = client.post(
        '/api/messages',
        data={'content': b64, 'recipient': 'alice', 'signature': sig},
        headers=headers,
    )
    assert resp.status_code == 201

    resp = client.get('/api/messages', headers=headers)
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data['messages']) == 1
    assert data['messages'][0]['content'] == b64
    assert data['messages'][0]['read'] is False

    # Recipient also sees it
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
    resp = client.post(
        '/api/messages',
        data={'content': b64, 'recipient': 'nonexistent', 'signature': sig},
        headers=headers,
    )
    assert resp.status_code == 404


def test_pinned_keys_endpoint(client):
    register_user(client, 'alice')
    register_user(client, 'bob')

    token = login_user(client, 'alice').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    bob_user = User.query.filter_by(username='bob').first()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import hashlib
    der = bob_user.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    fp = hashlib.sha256(der).hexdigest()

    resp = client.post('/api/pinned_keys', json={'username': 'bob', 'fingerprint': fp}, headers=headers)
    assert resp.status_code == 200
    resp = client.get('/api/pinned_keys', headers=headers)
    assert resp.status_code == 200
    assert {'username': 'bob', 'fingerprint': fp} in resp.get_json()['pinned_keys']


def test_push_token_and_notification(monkeypatch, client):
    register_user(client, 'alice')
    reg_bob = register_user(client, 'bob')
    pk_bob = decrypt_private_key(reg_bob)

    token_alice = login_user(client, 'alice').get_json()['access_token']
    headers_alice = {'Authorization': f'Bearer {token_alice}'}
    resp = client.post('/api/push-token', json={'token': 'abc', 'platform': 'web'}, headers=headers_alice)
    assert resp.status_code == 200

    calls = []
    monkeypatch.setattr('backend.resources.send_push_notifications', lambda uid, msg: calls.append((uid, msg)))

    token_bob = login_user(client, 'bob').get_json()['access_token']
    headers_bob = {'Authorization': f'Bearer {token_bob}'}
    b64 = base64.b64encode(b'hi').decode()
    sig = sign_content(pk_bob, b64)
    client.post('/api/messages', data={'content': b64, 'recipient': 'alice', 'signature': sig}, headers=headers_bob)

    assert calls


def test_push_token_delete(client):
    register_user(client, 'alice')
    token = login_user(client, 'alice').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}
    resp = client.post('/api/push-token', json={'token': 'tok', 'platform': 'web'}, headers=headers)
    assert resp.status_code == 200

    resp = client.delete('/api/push-token', json={'token': 'tok'}, headers=headers)
    assert resp.status_code == 200
    with app.app_context():
        from backend.models import PushToken
        assert PushToken.query.filter_by(token='tok').first() is None


def test_group_message_flow(client):
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')

    token_alice = login_user(client, 'alice').get_json()['access_token']
    headers_alice = {'Authorization': f'Bearer {token_alice}'}
    resp = client.post('/api/groups', json={'name': 'test'}, headers=headers_alice)
    assert resp.status_code == 201
    gid = resp.get_json()['id']

    token_bob = login_user(client, 'bob').get_json()['access_token']
    headers_bob = {'Authorization': f'Bearer {token_bob}'}
    # invite bob to group
    resp = client.post(
        f'/api/groups/{gid}/members',
        json={'username': 'bob'},
        headers=headers_alice,
    )
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

    client.post(
        f'/api/groups/{gid}/members',
        json={'username': 'bob'},
        headers=headers_alice,
    )

    long_content = base64.b64encode(b'A' * 1501).decode()
    sig = sign_content(pk_a, long_content)
    resp = client.post(
        f'/api/groups/{gid}/messages',
        data={'content': long_content, 'signature': sig},
        headers=headers_alice,
    )
    assert resp.status_code == 400


def test_group_key_distribution(client):
    register_user(client, 'alice')
    register_user(client, 'bob')
    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'g1'}, headers=headers_a)
    assert resp.status_code == 201
    gid = resp.get_json()['id']
    from backend.models import Group
    resp = client.post(
        f'/api/groups/{gid}/members',
        json={'username': 'bob'},
        headers=headers_a,
    )
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


def test_file_upload_download(client):
    reg = register_user(client, 'alice')
    pk = decrypt_private_key(reg)
    token = login_user(client, 'alice').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}
    from werkzeug.datastructures import FileStorage
    fs = FileStorage(stream=io.BytesIO(b'hello'), filename='hello.txt')
    resp = client.post('/api/files', data={'file': fs}, headers=headers, content_type='multipart/form-data')
    assert resp.status_code == 201
    fid = resp.get_json()['file_id']

    b64 = base64.b64encode(b'hi').decode()
    sig = sign_content(pk, b64)
    client.post('/api/messages', data={'content': b64, 'recipient': 'alice', 'file_id': fid, 'signature': sig}, headers=headers)

    resp = client.get(f'/api/files/{fid}', headers=headers)
    assert resp.status_code == 200
    assert resp.data == b'hello'


def test_file_download_authorization(client):
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')
    register_user(client, 'carol')

    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}

    from werkzeug.datastructures import FileStorage
    fs = FileStorage(stream=io.BytesIO(b'secret'), filename='secret.txt')
    resp = client.post('/api/files', data={'file': fs}, headers=headers_a, content_type='multipart/form-data')
    fid = resp.get_json()['file_id']

    b64 = base64.b64encode(b'hi').decode()
    sig = sign_content(pk_a, b64)
    client.post('/api/messages', data={'content': b64, 'recipient': 'bob', 'file_id': fid, 'signature': sig}, headers=headers_a)

    token_c = login_user(client, 'carol').get_json()['access_token']
    headers_c = {'Authorization': f'Bearer {token_c}'}
    resp = client.get(f'/api/files/{fid}', headers=headers_c)
    assert resp.status_code == 403


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


def test_group_message_read_requires_membership(client):
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')
    register_user(client, 'carol')

    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'grp'}, headers=headers_a)
    assert resp.status_code == 201
    gid = resp.get_json()['id']

    from backend.models import User
    resp = client.post(
        f'/api/groups/{gid}/members',
        json={'username': 'bob'},
        headers=headers_a,
    )
    assert resp.status_code == 201
    with app.app_context():
        bob_id = User.query.filter_by(username='bob').first().id

    b64 = base64.b64encode(b'hey').decode()
    sig = sign_content(pk_a, b64)
    resp = client.post(
        f'/api/groups/{gid}/messages',
        data={'content': b64, 'signature': sig},
        headers=headers_a,
    )
    assert resp.status_code == 201
    msg_id = resp.get_json()['id']

    token_carol = login_user(client, 'carol').get_json()['access_token']
    headers_c = {'Authorization': f'Bearer {token_carol}'}
    resp = client.post(f'/api/messages/{msg_id}/read', headers=headers_c)
    assert resp.status_code == 403


def test_group_message_id_usage(client):
    """Ensure the ID returned when sending a group message works for read and delete."""
    reg_a = register_user(client, 'alice')
    pk_a = decrypt_private_key(reg_a)
    register_user(client, 'bob')

    token_a = login_user(client, 'alice').get_json()['access_token']
    headers_a = {'Authorization': f'Bearer {token_a}'}
    resp = client.post('/api/groups', json={'name': 'room'}, headers=headers_a)
    gid = resp.get_json()['id']

    token_b = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}
    from backend.models import User
    resp = client.post(
        f'/api/groups/{gid}/members',
        json={'username': 'bob'},
        headers=headers_a,
    )
    assert resp.status_code == 201
    with app.app_context():
        bob_id = User.query.filter_by(username='bob').first().id

    b64 = base64.b64encode(b'hello').decode()
    sig = sign_content(pk_a, b64)
    resp = client.post(
        f'/api/groups/{gid}/messages',
        data={'content': b64, 'signature': sig},
        headers=headers_a,
    )
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

    resp = client.post(
        f'/api/groups/{gid}/members',
        json={'username': 'bob'},
        headers=headers_a,
    )
    assert resp.status_code == 201

    token_b = login_user(client, 'bob').get_json()['access_token']
    headers_b = {'Authorization': f'Bearer {token_b}'}
    from backend.models import User
    with app.app_context():
        bob_id = User.query.filter_by(username='bob').first().id

    resp = client.delete(f'/api/groups/{gid}/members/{bob_id}', headers=headers_b)
    assert resp.status_code == 200

    resp = client.get(f'/api/groups/{gid}/messages', headers=headers_b)
    assert resp.status_code == 403


def test_users_endpoint(client):
    register_user(client, 'alice')
    register_user(client, 'bob')
    token = login_user(client, 'alice').get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    resp = client.get('/api/users', headers=headers)
    assert resp.status_code == 200
    names = resp.get_json()['users']
    assert 'alice' in names and 'bob' in names

    resp = client.get('/api/users?q=bo', headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()['users'] == ['bob']
