from flask_restful import Resource, reqparse
from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import os
from models import User, Message
from app import db, app, socketio
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import json


# Request parser for user registration
user_parser = reqparse.RequestParser()
user_parser.add_argument('username', required=True, help="Username is required.")
user_parser.add_argument('email', required=True, help="Email is required.")
user_parser.add_argument('password', required=True, help="Password is required.")
user_parser.add_argument('publicKey', required=True, help="Public key is required.")

# Request parser for messages
message_parser = reqparse.RequestParser()
message_parser.add_argument('content', required=True, help="Content is required.")

# Token serializer (legacy).  JWT is now used instead of this custom mechanism.
# s = Serializer(app.config['SECRET_KEY'], expires_in=3600)

class Register(Resource):
    def post(self):
        # Parse the request data
        data = user_parser.parse_args()

        # Check if the user already exists
        user = User.query.filter_by(username=data['username']).first()
        if user:
            return {"message": "A user with that username already exists."}, 400

        # Hash the password
        hashed_password = generate_password_hash(data['password'], method='sha256')
        public_key_pem = data["publicKey"]
        new_user = User(username=data["username"], email=data["email"], password_hash=hashed_password, public_key_pem=public_key_pem)
        db.session.add(new_user)
        db.session.commit()
        return {"message": "User registered successfully."}, 201



class Login(Resource):
    def post(self):
        data = request.get_json()

        # Query the database for the user with the given username
        user = User.query.filter_by(username=data['username']).first()

        if user and check_password_hash(user.password_hash, data['password']):
            access_token = create_access_token(identity=user.id)
            return {'access_token': access_token}, 200
        else:
            return {'message': 'Invalid username or password'}, 401


class PublicKey(Resource):
    """Return the public key for the given username."""

    @jwt_required()
    def get(self, username):
        user = User.query.filter_by(username=username).first()
        if not user:
            return {"message": "User not found"}, 404
        return {"public_key": user.public_key_pem}

class Messages(Resource):
    # Retrieve all messages. Requires a valid JWT token.
    @jwt_required()
    def get(self):
        messages = Message.query.all()
        message_list = [
            {
                "id": msg.id,
                "content": msg.content,
                "timestamp": msg.timestamp,
                "user_id": msg.user_id,
            }
            for msg in messages
        ]
        return {"messages": message_list}

    # Send a new message. Rate limited via the limiter in app.py
    @jwt_required()
    def post(self):
        data = message_parser.parse_args()

        encrypted_content = data["content"]

        current_user_id = get_jwt_identity()
        new_message = Message(content=encrypted_content, user_id=current_user_id)
        db.session.add(new_message)
        db.session.commit()

        # Broadcast the encrypted message to connected clients via WebSockets
        socketio.emit(
            "new_message",
            {"content": encrypted_content, "user_id": current_user_id},
        )

        return {"message": "Message sent successfully."}, 201
