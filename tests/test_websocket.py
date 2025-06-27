"""WebSocket authentication tests."""

from backend.app import app, socketio


def test_websocket_requires_jwt(client):
    """Connections without a JWT should be rejected."""
    ws = socketio.test_client(app, flask_test_client=client)
    assert not ws.is_connected()
