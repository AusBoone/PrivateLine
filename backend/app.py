"""Application factory and global objects for the backend."""

import os
from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import (
    JWTManager,
    get_jwt_identity,
    verify_jwt_in_request,
)
from flask_socketio import SocketIO, disconnect, join_room
import redis
from dotenv import load_dotenv
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

# Load environment variables from a .env file if present.  This keeps
# secret values such as JWT_SECRET_KEY out of source control.
load_dotenv()

# Initialize Sentry for error monitoring when a DSN is provided
sentry_dsn = os.environ.get("SENTRY_DSN")
if sentry_dsn:
    sentry_sdk.init(
        dsn=sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=1.0,
    )

# Initialize Flask app and extensions
app = Flask(__name__)

# Configure allowed origins for CORS and WebSocket connections. A comma
# separated list in the ``CORS_ORIGINS`` environment variable restricts both
# Flask and Socket.IO traffic. The default "*" permits all origins.
_cors_origins = os.environ.get("CORS_ORIGINS", "*")
if _cors_origins != "*":
    _cors_origins = [o.strip() for o in _cors_origins.split(",")]

# Enable Cross-Origin Resource Sharing (CORS) for the app
CORS(app, supports_credentials=True, origins=_cors_origins)

# SocketIO is used for pushing real-time updates to connected clients. The same
# ``CORS_ORIGINS`` setting controls which WebSocket origins are accepted.
socketio = SocketIO(app, cors_allowed_origins=_cors_origins)

# Initialize rate limiting with a custom key function that prefers the
# authenticated user id and falls back to the client's IP address.
def rate_limit_key():
    """Return a string used for rate limit tracking for the current request."""
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            return identity
    except Exception:
        pass
    return get_remote_address()

_redis_url = os.environ.get("REDIS_URL")
_limiter_kwargs = {"key_func": rate_limit_key, "app": app}
if _redis_url:
    _limiter_kwargs["storage_uri"] = _redis_url
limiter = Limiter(**_limiter_kwargs)

# Configure app settings. Values can be overridden via environment variables.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URI', 'sqlite:///secure_messaging.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
_jwt_secret = os.environ.get('JWT_SECRET_KEY')
if not _jwt_secret:
    raise RuntimeError('JWT_SECRET_KEY environment variable not set')
app.config['JWT_SECRET_KEY'] = _jwt_secret
app.config['JWT_TOKEN_LOCATION'] = ["headers", "cookies"]
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

# Initialize database and migration tools
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize the RESTful API
api = Api(app)

# Initialize JWTManager for handling JWT authentication
jwt = JWTManager(app)

# --- JWT Token Blocklist ---
# Token identifiers (jti) are stored in memory by default.  When a REDIS_URL is
# configured, use Redis so revoked tokens persist across restarts.

class RedisBlocklist:
    """Simple set-like interface backed by Redis."""

    def __init__(self, client):
        self.client = client

    def add(self, jti: str) -> None:
        self.client.sadd("token_blocklist", jti)

    def __contains__(self, jti: str) -> bool:  # pragma: no cover - trivial
        return bool(self.client.sismember("token_blocklist", jti))


if _redis_url:
    try:
        _redis_client = redis.from_url(_redis_url)
        token_blocklist = RedisBlocklist(_redis_client)
    except Exception:
        # Fallback to in-memory store if Redis is unreachable
        token_blocklist = set()
else:
    token_blocklist = set()

@jwt.token_in_blocklist_loader
def token_in_blocklist_callback(jwt_header, jwt_payload):
    """Check whether the given JWT has been revoked."""
    return jwt_payload.get("jti") in token_blocklist

# Import resources after initializing app components to avoid circular imports
from .resources import (
    Register,
    Login,
    Messages,
    PublicKey,
    Users,
    Groups,
    GroupMembers,
    GroupMemberResource,
    GroupKey,
    GroupMessages,
    FileUpload,
    FileDownload,
    PinnedKeys,
    AccountSettings,
    RefreshToken,
    RevokeToken,
    PushTokenResource,
    MessageResource,
    MessageRead,
)

# Reject WebSocket connections that do not provide a valid JWT.
@socketio.on("connect")
def socket_connect():
    """Join rooms for the authenticated user when a WebSocket connects."""
    # If the token is missing or invalid the connection will be rejected.
    try:
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        join_room(str(user_id))
        # Join all group rooms so the user receives group messages in real time
        from .models import GroupMember
        groups = GroupMember.query.filter_by(user_id=user_id).all()
        for g in groups:
            join_room(str(g.group_id))
    except Exception:
        app.logger.warning("WebSocket connection rejected due to missing or invalid token")
        disconnect()

# Apply rate limiting on the messages resource
limiter.limit("50/minute")(Messages)

# Register resources and routes
api.add_resource(Register, '/api/register')
api.add_resource(Login, '/api/login')
api.add_resource(Messages, '/api/messages')
api.add_resource(PublicKey, '/api/public_key/<string:username>')
api.add_resource(Users, '/api/users')
api.add_resource(Groups, '/api/groups')
api.add_resource(GroupMembers, '/api/groups/<int:group_id>/members')
api.add_resource(GroupMemberResource, '/api/groups/<int:group_id>/members/<int:user_id>')
api.add_resource(GroupKey, '/api/groups/<int:group_id>/key')
api.add_resource(GroupMessages, '/api/groups/<int:group_id>/messages')
api.add_resource(FileUpload, '/api/files')
api.add_resource(FileDownload, '/api/files/<int:file_id>')
api.add_resource(PinnedKeys, '/api/pinned_keys')
api.add_resource(AccountSettings, '/api/account-settings')
api.add_resource(RefreshToken, '/api/refresh')
api.add_resource(RevokeToken, '/api/revoke')
api.add_resource(PushTokenResource, '/api/push-token')
api.add_resource(MessageResource, '/api/messages/<int:message_id>')
api.add_resource(MessageRead, '/api/messages/<int:message_id>/read')

# Run the development server only when executed directly.
if __name__ == '__main__':
    # socketio.run enables WebSocket support alongside the Flask app
    socketio.run(app, debug=True)
