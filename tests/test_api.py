import json
import pytest

# These imports will fail if Flask and related dependencies are not installed.
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


def test_register_and_login(client):
    resp = register_user(client)
    assert resp.status_code == 201
    payload = resp.get_json()
    assert 'encrypted_private_key' in payload

    resp = login_user(client)
    assert resp.status_code == 200
    assert 'access_token' in resp.get_json()


def test_message_flow(client):
    register_user(client, 'bob')
    login = login_user(client, 'bob')
    token = login.get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}

    resp = client.post('/api/messages', data={'content': 'hello'}, headers=headers)
    assert resp.status_code == 201

    resp = client.get('/api/messages', headers=headers)
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data['messages']) == 1
