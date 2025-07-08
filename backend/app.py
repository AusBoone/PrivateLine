"""Application factory and global objects for the backend.

This module configures the Flask application used by the REST and WebSocket
APIs. Database sessions, JWT authentication and rate limiting are initialized
here. Periodic cleanup tasks remove expired messages, push tokens and files.
Messages flagged ``delete_on_read`` are purged immediately once read.

2025 update: CSRF protection for JWT cookies is now enabled by default via
``JWT_COOKIE_CSRF_PROTECT``. All POST/PUT/DELETE endpoints therefore require the
``X-CSRF-TOKEN`` header or a ``csrf_token`` form field when authentication
cookies are used.
"""

import os
from flask import Flask, send_from_directory
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
from flask_jwt_extended.exceptions import JWTExtendedException
from flask_socketio import SocketIO, disconnect, join_room
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import redis
from pathlib import Path
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
# Initialize application-wide logging before other components.
from .logging_config import init_logging

init_logging()


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


def _apply_security_headers(resp):
    """Attach common security headers to every HTTP response.

    The function reads optional environment variables to allow deployments to
    customize the ``Content-Security-Policy`` header and to enable HSTS. All
    API endpoints are marked ``Cache-Control: no-store`` to avoid leaking
    sensitive data through intermediary caches.
    """

    csp = os.environ.get("CONTENT_SECURITY_POLICY", "default-src 'none'")
    hsts_enabled = os.environ.get("HSTS_ENABLED", "false").lower() == "true"

    resp.headers.setdefault("Content-Security-Policy", csp)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    if hsts_enabled:
        resp.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return resp


app.after_request(_apply_security_headers)


# Initialize rate limiting with a custom key function that prefers the
# authenticated user id and falls back to the client's IP address.
def rate_limit_key():
    """Return a string used for rate limit tracking for the current request."""
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            return identity
    except JWTExtendedException:
        pass
    return get_remote_address()


_redis_url = os.environ.get("REDIS_URL")
_limiter_kwargs = {"key_func": rate_limit_key, "app": app}
if _redis_url:
    _limiter_kwargs["storage_uri"] = _redis_url
limiter = Limiter(**_limiter_kwargs)

# Configure app settings. Values can be overridden via environment variables.
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URI", "sqlite:///secure_messaging.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
_jwt_secret = os.environ.get("JWT_SECRET_KEY")
if not _jwt_secret:
    raise RuntimeError("JWT_SECRET_KEY environment variable not set")
app.config["JWT_SECRET_KEY"] = _jwt_secret
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config["JWT_COOKIE_SECURE"] = (
    os.environ.get("JWT_COOKIE_SECURE", "false").lower() == "true"
)
app.config["JWT_COOKIE_SAMESITE"] = os.environ.get("JWT_COOKIE_SAMESITE", "Lax")
# Enable CSRF protection for JWT cookies by default. Deployments may
# explicitly set ``JWT_COOKIE_CSRF_PROTECT=false`` if cookies are not used or a
# reverse proxy handles CSRF validation.
app.config["JWT_COOKIE_CSRF_PROTECT"] = (
    os.environ.get("JWT_COOKIE_CSRF_PROTECT", "true").lower() == "true"
)

# Maximum age in days for stored push notification tokens. Tokens older than
# this are automatically removed by ``clean_expired_push_tokens``.
PUSH_TOKEN_TTL_DAYS = int(os.environ.get("PUSH_TOKEN_TTL_DAYS", "30"))
# Maximum age for uploaded files before they are purged. ``clean_expired_files``
# uses this value when a :class:`File` instance does not specify a custom
# retention period.
FILE_RETENTION_DAYS = int(os.environ.get("FILE_RETENTION_DAYS", "30"))

# Initialize database and migration tools
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize the RESTful API
api = Api(app)

# Initialize JWTManager for handling JWT authentication
jwt = JWTManager(app)

# Schedule periodic cleanup of expired messages. The :func:`clean_expired_messages`
# function runs every minute to remove messages past their ``expires_at`` time
# so that ephemeral conversations do not linger on the server indefinitely.
scheduler = BackgroundScheduler()


def clean_expired_messages() -> None:
    """Remove messages past their expiration or user retention period."""
    from datetime import timedelta
    from .models import Message, User

    with app.app_context():
        now = datetime.utcnow()

        # Delete any messages with an explicit expires_at timestamp in the past.
        expired = Message.query.filter(
            Message.expires_at.is_not(None), Message.expires_at <= now
        ).all()
        for msg in expired:
            if db.session.get(Message, msg.id) is None:
                continue
            db.session.delete(msg)

        # Per-user retention policy: prune read messages older than the user's
        # configured duration. Each message may be checked multiple times if it
        # involves multiple users, but deletion is idempotent.
        users = User.query.all()
        for user in users:
            cutoff = now - timedelta(days=user.message_retention_days)
            old_msgs = Message.query.filter(
                Message.read.is_(True),
                Message.timestamp <= cutoff,
                ((Message.sender_id == user.id) | (Message.recipient_id == user.id)),
            ).all()
            for msg in old_msgs:
                if db.session.get(Message, msg.id) is None:
                    continue
                db.session.delete(msg)

        if expired or users:
            db.session.commit()
            from .resources import remove_orphan_files

            remove_orphan_files()


def clean_expired_push_tokens() -> None:
    """Remove push tokens older than ``PUSH_TOKEN_TTL_DAYS`` days."""
    from datetime import timedelta
    from .models import PushToken

    cutoff = datetime.utcnow() - timedelta(days=PUSH_TOKEN_TTL_DAYS)
    with app.app_context():
        expired = PushToken.query.filter(PushToken.created_at <= cutoff).all()
        if expired:
            for tok in expired:
                db.session.delete(tok)
            db.session.commit()


def clean_expired_files() -> None:
    """Remove files older than their configured retention period."""
    from datetime import timedelta
    from .models import File, Message

    now = datetime.utcnow()
    with app.app_context():
        candidates = File.query.all()
        removed = False
        for f in candidates:
            age_limit = timedelta(days=f.file_retention_days)
            if f.created_at <= now - age_limit:
                # Detach messages referencing the file before deletion to avoid
                # foreign key violations.
                Message.query.filter_by(file_id=f.id).update({"file_id": None})
                db.session.delete(f)
                removed = True
        if removed:
            db.session.commit()


scheduler.add_job(clean_expired_messages, "interval", minutes=1)
scheduler.add_job(clean_expired_push_tokens, "interval", hours=1)
scheduler.add_job(clean_expired_files, "interval", hours=1)

# Avoid background threads during unit tests which manipulate the database
# concurrently. The scheduler only runs in normal operation.
if os.environ.get("TESTING") != "1":
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

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
    except redis.RedisError:
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
    DeleteAccount,
    RefreshToken,
    RevokeToken,
    PushTokenResource,
    MessageResource,
    MessageRead,
    UnreadCount,
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
    except JWTExtendedException:
        app.logger.warning(
            "WebSocket connection rejected due to missing or invalid token"
        )
        disconnect()


# Apply rate limiting on the messages resource
limiter.limit("50/minute")(Messages)

# Register resources and routes
api.add_resource(Register, "/api/register")
api.add_resource(Login, "/api/login")
api.add_resource(Messages, "/api/messages")
api.add_resource(PublicKey, "/api/public_key/<string:username>")
api.add_resource(Users, "/api/users")
api.add_resource(Groups, "/api/groups")
api.add_resource(GroupMembers, "/api/groups/<int:group_id>/members")
api.add_resource(
    GroupMemberResource, "/api/groups/<int:group_id>/members/<int:user_id>"
)
api.add_resource(GroupKey, "/api/groups/<int:group_id>/key")
api.add_resource(GroupMessages, "/api/groups/<int:group_id>/messages")
api.add_resource(FileUpload, "/api/files")
api.add_resource(FileDownload, "/api/files/<int:file_id>")
api.add_resource(PinnedKeys, "/api/pinned_keys")
api.add_resource(DeleteAccount, "/api/account")


# Serve the generated OpenAPI spec and minimal Swagger UI
@app.route("/api/openapi.yaml")
def openapi_spec():
    """Return the OpenAPI specification YAML."""
    docs_path = Path(__file__).resolve().parent.parent / "docs"
    return send_from_directory(docs_path, "openapi.yaml")


@app.route("/api/docs")
def api_docs():
    """Serve an embedded Swagger UI for browsing the API."""
    return """<!DOCTYPE html><html><head><title>API Docs</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:"/api/openapi.yaml",dom_id:"#swagger-ui"});</script></body></html>"""


api.add_resource(AccountSettings, "/api/account-settings")
api.add_resource(RefreshToken, "/api/refresh")
api.add_resource(RevokeToken, "/api/revoke")
api.add_resource(PushTokenResource, "/api/push-token")
api.add_resource(MessageResource, "/api/messages/<int:message_id>")
api.add_resource(MessageRead, "/api/messages/<int:message_id>/read")
api.add_resource(UnreadCount, "/api/unread_count")

# Run the development server only when executed directly.
if __name__ == "__main__":
    # socketio.run enables WebSocket support alongside the Flask app. Debug mode
    # is only enabled when FLASK_DEBUG=1 is present in the environment so that
    # production deployments default to a safe configuration.
    socketio.run(app, debug=os.getenv("FLASK_DEBUG") == "1")
