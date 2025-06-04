import json
import os
import base64
import pytest
from base64 import b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# These imports will fail if Flask and related dependencies are not installed.
# Ensure an AES key is available for the backend before it is imported. Tests
# run without a .env file so we generate a deterministic key on the fly.
os.environ.setdefault("AES_KEY", base64.b64encode(os.urandom(32)).decode())

from backend.app import app, db
from backend.models import User, Message

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
    with app.test_client() as client:
        yield client
    with app.app_context():
        db.drop_all()


def register_user(client, username='alice'):
    data = {
        'username': username,
        'email': f'{username}@example.com',
        'password': 'secret',
    }
    return client.post('/api/register', data=data)


def login_user(client, username='alice'):
    return client.post('/api/login', json={
        'username': username,
        'password': 'secret',
    })


def test_register_missing_fields(client):
    resp = client.post('/api/register', data={'username': 'x'})
    assert resp.status_code == 400


def test_login_invalid_credentials(client):
    register_user(client, 'dave')
    resp = client.post('/api/login', json={'username': 'dave', 'password': 'bad'})
    assert resp.status_code == 401


def test_register_and_login(client):
    resp = register_user(client)
    assert resp.status_code == 201
    payload = resp.get_json()
    assert {'encrypted_private_key', 'salt', 'nonce'} <= payload.keys()

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
    register_user(client, 'bob')
    login = login_user(client, 'bob')
    token = login.get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    b64 = base64.b64encode(b'hello').decode()
    resp = client.post('/api/messages', data={'content': b64}, headers=headers)
    assert resp.status_code == 201

    resp = client.get('/api/messages', headers=headers)
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data['messages']) == 1
    assert data['messages'][0]['content'] == b64


def test_message_privacy(client):
    register_user(client, 'eve')
    token_eve = login_user(client, 'eve').get_json()['access_token']
    headers_eve = {'Authorization': f'Bearer {token_eve}'}
    encoded = base64.b64encode(b'secret').decode()
    client.post('/api/messages', data={'content': encoded}, headers=headers_eve)

    register_user(client, 'mallory')
    token_mallory = login_user(client, 'mallory').get_json()['access_token']
    headers_mallory = {'Authorization': f'Bearer {token_mallory}'}

    resp = client.get('/api/messages', headers=headers_mallory)
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
