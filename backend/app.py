"""Application factory and global objects for the backend.

This module configures the Flask application used by the REST and WebSocket
APIs. Database sessions, JWT authentication and rate limiting are initialized
here. Periodic cleanup tasks remove expired messages, push tokens and files.
Messages flagged ``delete_on_read`` are purged immediately once read.

2025 update: CSRF protection for JWT cookies is now enabled by default via
``JWT_COOKIE_CSRF_PROTECT``. All POST/PUT/DELETE endpoints therefore require the
``X-CSRF-TOKEN`` header or a ``csrf_token`` form field when authentication
cookies are used.

2025 refactor: message cleanup now uses set-based SQL statements instead of
per-user loops so large deployments prune expired data efficiently.

2026 security hardening: cross-origin requests are disabled by default until
the ``CORS_ORIGINS`` environment variable explicitly lists allowed origins.
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
# Flask and Socket.IO traffic. Without an explicit setting, cross-origin
# requests are denied to avoid unintentionally exposing the API.
_cors_origins = os.environ.get("CORS_ORIGINS")
if _cors_origins:
    # Split the comma separated list and strip whitespace so entries such as
    # "https://example.com, https://other.com" are handled correctly. Empty
    # segments are ignored to prevent accidental wildcard matches.
    _cors_origins = [origin.strip() for origin in _cors_origins.split(",") if origin.strip()]
else:
    # An empty list means no origins are allowed. Browsers will refuse to expose
    # responses to scripts from other origins because the ``Access-Control-Allow-Origin``
    # header is absent. This requires deployers to deliberately opt in by setting
    # ``CORS_ORIGINS``.
    _cors_origins = []

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
    """Remove messages past their expiration or retention policies.

    The previous implementation iterated over every user and evaluated
    retention rules in Python. That approach issued numerous small queries and
    scaled poorly. The refactored version below performs set-based ``DELETE``
    statements driven by SQL subqueries so that cleanup cost grows primarily
    with the number of messages requiring removal rather than total user
    count. All deletions are committed in a single transaction.
    """

    from sqlalchemy import and_, func, literal, or_, select
    from .models import ConversationRetention, Group, Message, User

    with app.app_context():
        now = datetime.utcnow()
        now_seconds = int(now.timestamp())

        # ``strftime`` is SQLite specific while ``extract`` works for PostgreSQL.
        # Selecting the appropriate function keeps the comparison portable.
        if db.session.bind.dialect.name == "sqlite":
            msg_ts = func.strftime("%s", Message.timestamp)
        else:  # pragma: no cover - exercised in non-sqlite deployments
            msg_ts = func.extract("epoch", Message.timestamp)

        # --- Explicit per-message expiration ---------------------------------
        expired_stmt = db.delete(Message).where(
            Message.expires_at.is_not(None), Message.expires_at <= now
        )
        db.session.execute(expired_stmt.execution_options(synchronize_session=False))

        # --- Direct conversation retention -----------------------------------
        sender_retention = func.coalesce(
            # Retention override defined by the sender
            select(ConversationRetention.retention_days)
            .where(
                ConversationRetention.owner_id == Message.sender_id,
                ConversationRetention.peer_id == Message.recipient_id,
            )
            .correlate(Message)
            .scalar_subquery(),
            # Fallback to the sender's default retention setting
            select(User.message_retention_days)
            .where(User.id == Message.sender_id)
            .correlate(Message)
            .scalar_subquery(),
        )

        recipient_retention = func.coalesce(
            select(ConversationRetention.retention_days)
            .where(
                ConversationRetention.owner_id == Message.recipient_id,
                ConversationRetention.peer_id == Message.sender_id,
            )
            .correlate(Message)
            .scalar_subquery(),
            select(User.message_retention_days)
            .where(User.id == Message.recipient_id)
            .correlate(Message)
            .scalar_subquery(),
        )

        sender_seconds = sender_retention * literal(86400)
        recipient_seconds = recipient_retention * literal(86400)

        direct_condition = and_(
            Message.group_id.is_(None),
            Message.read.is_(True),
            or_(
                now_seconds - msg_ts >= sender_seconds,
                now_seconds - msg_ts >= recipient_seconds,
            ),
        )

        # --- Group conversation retention ------------------------------------
        group_retention = func.coalesce(
            select(Group.retention_days)
            .where(Group.id == Message.group_id)
            .correlate(Message)
            .scalar_subquery(),
            select(User.message_retention_days)
            .where(User.id == Message.sender_id)
            .correlate(Message)
            .scalar_subquery(),
        )
        group_seconds = group_retention * literal(86400)

        group_condition = and_(
            Message.group_id.is_not(None),
            Message.read.is_(True),
            now_seconds - msg_ts >= group_seconds,
        )

        retention_stmt = db.delete(Message).where(or_(direct_condition, group_condition))
        db.session.execute(retention_stmt.execution_options(synchronize_session=False))

        # Commit once after all deletions to minimize database overhead.
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
    GroupRetention,
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
    ConversationRetentionResource,
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
#
# ``Messages`` enforces a ``50/minute`` limit via its class-level ``decorators``
# attribute. No additional wrapper is needed at registration time.

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
api.add_resource(GroupRetention, "/api/groups/<int:group_id>/retention")
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
api.add_resource(ConversationRetentionResource, "/api/conversations/<string:username>/retention")

# Run the development server only when executed directly.
if __name__ == "__main__":
    # socketio.run enables WebSocket support alongside the Flask app. Debug mode
    # is only enabled when FLASK_DEBUG=1 is present in the environment so that
    # production deployments default to a safe configuration.
    socketio.run(app, debug=os.getenv("FLASK_DEBUG") == "1")
