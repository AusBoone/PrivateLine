"""Generate OpenAPI specification for PrivateLine API using ``apispec``.

This module defines small Marshmallow schemas representing the payloads used by
the REST API and maps each Flask-RESTful resource to an OpenAPI path. Running
the script produces ``docs/openapi.yaml`` which is served by the development
server for interactive documentation.

2024 update: paths for message retention settings were added and the
``MessageRequest`` schema gained a ``delete_on_read`` flag to document ephemeral
messages that disappear once read.
"""

import os

from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from marshmallow import Schema, fields


class RegisterRequestSchema(Schema):
    """Payload required when registering a new user."""

    username = fields.Str(required=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True)


class RegisterResponseSchema(Schema):
    """Values returned after successful registration."""

    encrypted_private_key = fields.Str()
    salt = fields.Str()
    nonce = fields.Str()
    fingerprint = fields.Str()


class LoginRequestSchema(Schema):
    """Credentials used to obtain a JWT token."""

    username = fields.Str(required=True)
    password = fields.Str(required=True)


class LoginResponseSchema(Schema):
    """Simple schema for the access token response."""

    access_token = fields.Str()


class MessageRequestSchema(Schema):
    """Data required to create a message."""

    content = fields.Str(required=True)
    recipient = fields.Str(required=False)
    group_id = fields.Int(required=False)
    file_id = fields.Int(required=False)
    # Optional ISO8601 timestamp indicating when the message should
    # expire and be removed by the server. Clients may hide expired
    # messages locally as well for a consistent experience.
    expires_at = fields.DateTime(required=False)
    # When true the server deletes the message immediately after it is marked
    # as read. This mirrors the ``delete_on_read`` flag accepted by the REST
    # endpoint so clients know that these messages are never persisted beyond
    # the first read.
    delete_on_read = fields.Bool(required=False)
    signature = fields.Str(required=True)


class MessageResponseSchema(Schema):
    """Data returned when listing messages."""

    id = fields.Int()
    content = fields.Str()
    timestamp = fields.Str()
    sender_id = fields.Int()
    recipient_id = fields.Int(allow_none=True)
    file_id = fields.Int(allow_none=True)
    read = fields.Bool()
    expires_at = fields.Str()


class GenericMessageSchema(Schema):
    """Simple message wrapper used for many responses."""

    message = fields.Str()


def build_spec() -> APISpec:
    """Return an APISpec describing all REST endpoints."""

    spec = APISpec(
        title="PrivateLine API",
        version="1.0.0",
        openapi_version="3.0.3",
        plugins=[MarshmallowPlugin()],
    )

    # Register schemas so they can be referenced in path definitions
    spec.components.schema("RegisterRequest", schema=RegisterRequestSchema)
    spec.components.schema("RegisterResponse", schema=RegisterResponseSchema)
    spec.components.schema("LoginRequest", schema=LoginRequestSchema)
    spec.components.schema("LoginResponse", schema=LoginResponseSchema)
    spec.components.schema("MessageRequest", schema=MessageRequestSchema)
    spec.components.schema("MessageResponse", schema=MessageResponseSchema)
    spec.components.schema("GenericMessage", schema=GenericMessageSchema)

    # Each path definition below maps directly to a Flask-RESTful resource.
    spec.path(
        path="/api/register",
        operations={
            "post": {
                "summary": "Create a new user",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": "RegisterRequest"
                        },
                        "application/x-www-form-urlencoded": {
                            "schema": "RegisterRequest"
                        },
                    },
                },
                "responses": {
                    "201": {
                        "description": "User created",
                        "content": {
                            "application/json": {
                                "schema": "RegisterResponse"
                            }
                        },
                    },
                    "400": {"description": "Validation error"},
                },
            }
        },
    )

    spec.path(
        path="/api/login",
        operations={
            "post": {
                "summary": "Authenticate and obtain access token",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": "LoginRequest"
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Authentication succeeded",
                        "content": {
                            "application/json": {
                                "schema": "LoginResponse"
                            }
                        },
                    },
                    "401": {"description": "Invalid credentials"},
                },
            }
        },
    )

    spec.path(
        path="/api/messages",
        operations={
            "get": {
                "summary": "Retrieve messages for the user",
                "parameters": [
                    {
                        "in": "query",
                        "name": "limit",
                        "schema": {"type": "integer", "default": 50},
                        "required": False,
                    },
                    {
                        "in": "query",
                        "name": "offset",
                        "schema": {"type": "integer", "default": 0},
                        "required": False,
                    },
                ],
                "responses": {
                    "200": {
                        "description": "List of messages",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "messages": {
                                            "type": "array",
                                            "items": "MessageResponse",
                                        }
                                    },
                                }
                            }
                        },
                    }
                },
            },
            "post": {
                "summary": "Send a new message",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": "MessageRequest"
                        },
                        "multipart/form-data": {
                            "schema": "MessageRequest"
                        },
                    },
                },
                "responses": {
                    "201": {"description": "Message stored"},
                    "400": {"description": "Invalid input"},
                },
            },
        },
    )

    spec.path(
        path="/api/public_key/{username}",
        operations={
            "get": {
                "summary": "Return public key for user",
                "parameters": [
                    {
                        "in": "path",
                        "name": "username",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Public key retrieved",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"public_key": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "404": {"description": "User not found"},
                },
            }
        },
    )

    # Additional endpoints are described more generically to keep the
    # specification concise. Only the most relevant parameters and response
    # structures are documented explicitly.

    spec.path(
        path="/api/users",
        operations={
            "get": {
                "summary": "List usernames",
                "parameters": [
                    {
                        "in": "query",
                        "name": "q",
                        "schema": {"type": "string"},
                        "required": False,
                    }
                ],
                "responses": {"200": {"description": "User list"}},
            }
        },
    )

    spec.path(
        path="/api/groups",
        operations={
            "get": {"summary": "List chat groups", "responses": {"200": {"description": "Group list"}}},
            "post": {"summary": "Create group", "responses": {"201": {"description": "Group created"}}},
        },
    )

    spec.path(
        path="/api/groups/{group_id}/members",
        operations={
            "post": {
                "summary": "Join or invite user",
                "parameters": [
                    {
                        "in": "path",
                        "name": "group_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    }
                ],
                "responses": {"201": {"description": "Added"}, "403": {"description": "Not a member"}},
            }
        },
    )

    spec.path(
        path="/api/groups/{group_id}/members/{user_id}",
        operations={
            "delete": {
                "summary": "Remove a member",
                "parameters": [
                    {
                        "in": "path",
                        "name": "group_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    },
                    {
                        "in": "path",
                        "name": "user_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    },
                ],
                "responses": {"200": {"description": "Removed"}},
            }
        },
    )

    spec.path(
        path="/api/groups/{group_id}/key",
        operations={
            "get": {
                "summary": "Retrieve group key",
                "parameters": [
                    {
                        "in": "path",
                        "name": "group_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    }
                ],
                "responses": {"200": {"description": "Key returned"}},
            },
            "put": {
                "summary": "Rotate group key",
                "parameters": [
                    {
                        "in": "path",
                        "name": "group_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    }
                ],
                "responses": {"200": {"description": "Key rotated"}},
            },
        },
    )

    spec.path(
        path="/api/groups/{group_id}/retention",
        operations={
            "put": {
                "summary": "Configure group retention",
                "parameters": [
                    {
                        "in": "path",
                        "name": "group_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"retention_days": {"type": "integer"}},
                                "required": ["retention_days"],
                            }
                        }
                    },
                },
                "responses": {"200": {"description": "updated"}},
            }
        },
    )

    spec.path(
        path="/api/groups/{group_id}/messages",
        operations={
            "get": {
                "summary": "List group messages",
                "parameters": [
                    {
                        "in": "path",
                        "name": "group_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    },
                    {
                        "in": "query",
                        "name": "limit",
                        "schema": {"type": "integer", "default": 50},
                        "required": False,
                    },
                    {
                        "in": "query",
                        "name": "offset",
                        "schema": {"type": "integer", "default": 0},
                        "required": False,
                    },
                ],
                "responses": {"200": {"description": "Messages returned"}},
            },
            "post": {
                "summary": "Send group message",
                "parameters": [
                    {
                        "in": "path",
                        "name": "group_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {"schema": "MessageRequest"}
                    },
                },
                "responses": {"201": {"description": "Message stored"}},
            },
        },
    )

    spec.path(
        path="/api/files",
        operations={
            "post": {
                "summary": "Upload encrypted file",
                "requestBody": {
                    "required": True,
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "type": "object",
                                "properties": {"file": {"type": "string", "format": "binary"}},
                                "required": ["file"],
                            }
                        }
                    },
                },
                "responses": {"201": {"description": "File stored"}},
            }
        },
    )

    spec.path(
        path="/api/files/{file_id}",
        operations={
            "get": {
                "summary": "Download file",
                "parameters": [
                    {
                        "in": "path",
                        "name": "file_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    }
                ],
                "responses": {
                    "200": {"description": "File contents"},
                    "404": {
                        "description": "File not found or download limit reached"
                    },
                },
            }
        },
    )

    spec.path(
        path="/api/pinned_keys",
        operations={
            "get": {"summary": "List pinned keys", "responses": {"200": {"description": "List returned"}}},
            "post": {"summary": "Store pinned key", "responses": {"200": {"description": "Stored"}}},
        },
    )

    spec.path(
        path="/api/account",
        operations={"delete": {"summary": "Delete account", "responses": {"200": {"description": "Deleted"}}}},
    )

    spec.path(
        path="/api/account-settings",
        operations={"put": {"summary": "Update account", "responses": {"200": {"description": "Updated"}}}},
    )

    spec.path(
        path="/api/refresh",
        operations={"post": {"summary": "Refresh JWT", "responses": {"200": {"description": "Token issued"}}}},
    )

    spec.path(
        path="/api/revoke",
        operations={"post": {"summary": "Revoke JWT", "responses": {"200": {"description": "Revoked"}}}},
    )

    spec.path(
        path="/api/push-token",
        operations={
            "post": {"summary": "Store push token", "responses": {"200": {"description": "Stored"}}},
            "delete": {"summary": "Delete push token", "responses": {"200": {"description": "Deleted"}}},
        },
    )

    spec.path(
        path="/api/messages/{message_id}",
        operations={
            "delete": {
                "summary": "Delete message",
                "parameters": [
                    {
                        "in": "path",
                        "name": "message_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    }
                ],
                "responses": {"200": {"description": "Deleted"}},
            }
        },
    )

    spec.path(
        path="/api/messages/{message_id}/read",
        operations={
            "post": {
                "summary": "Mark message as read",
                "parameters": [
                    {
                        "in": "path",
                        "name": "message_id",
                        "schema": {"type": "integer"},
                        "required": True,
                    }
                ],
                "responses": {"200": {"description": "Marked as read"}},
            }
        },
    )

    spec.path(
        path="/api/unread_count",
        operations={
            "get": {
                "summary": "Get unread message count",
                "description": "Return the number of unread direct and group messages for the authenticated user.",
                "responses": {"200": {"description": "Count returned"}},
            }
        },
    )

    spec.path(
        path="/api/conversations/{username}/retention",
        operations={
            "put": {
                "summary": "Set conversation retention",
                "parameters": [
                    {
                        "in": "path",
                        "name": "username",
                        "schema": {"type": "string"},
                        "required": True,
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"retention_days": {"type": "integer"}},
                                "required": ["retention_days"],
                            }
                        }
                    },
                },
                "responses": {"200": {"description": "updated"}},
            }
        },
    )

    return spec


if __name__ == "__main__":
    spec = build_spec()
    os.makedirs("docs", exist_ok=True)
    with open(os.path.join("docs", "openapi.yaml"), "w") as fh:
        fh.write(spec.to_yaml())

