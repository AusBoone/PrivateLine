from flask_restful import Resource, reqparse
from flask import request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from functools import wraps
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import os
from models import User, Message
from app import db, app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import json

# Fernet key for encryption
FERNET_KEY = os.environ.get('FERNET_KEY') or Fernet.generate_key()
cipher_suite = Fernet(FERNET_KEY)

# Request parser for user registration
user_parser = reqparse.RequestParser()
user_parser.add_argument('username', required=True, help="Username is required.")
user_parser.add_argument('email', required=True, help="Email is required.")
user_parser.add_argument('password', required=True, help="Password is required.")

# Request parser for messages
message_parser = reqparse.RequestParser()
message_parser.add_argument('content', required=True, help="Content is required.")

# Token serializer
s = Serializer(app.config['SECRET_KEY'], expires_in=3600)

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Token is missing.'}, 403

        try:
            data = s.loads(token)
        except:
            return {'message': 'Invalid token.'}, 403

        g.current_user = User.query.get(data['id'])
        return f(*args, **kwargs)
    return decorated

"""
The private key is encrypted using AES-256 in CBC mode, 
with a key derived from the user's password using PBKDF2. 
The encrypted private key, salt, and IV are then 
sent to the user encoded in base64.
"""
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

        # Generate key pair
        private_key, public_key_pem = User.generate_key_pair()

        # Encrypt the private key with the user's password
        password = data['password'].encode()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(128).padder()
        padded_private_key = padder.update(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )) + padder.finalize()
        encrypted_private_key = encryptor.update(padded_private_key) + encryptor.finalize()

        # Create a new user and add it to the database
        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password, public_key_pem=public_key_pem)
        db.session.add(new_user)
        db.session.commit()

        # Send encrypted private key and encryption details to the user
        return {
            "message": "User registered successfully.",
            "encrypted_private_key": b64encode(encrypted_private_key).decode(),
            "salt": b64encode(salt).decode(),
            "iv": b64encode(iv).decode()
        }, 201

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


class Messages(Resource):
    # Apply the authentication decorator
    @token_required
    def get(self):
        messages = Message.query.all()
        message_list = [{"id": msg.id, "content": cipher_suite.decrypt(msg.content.encode()).decode(), "timestamp": msg.timestamp, "user_id": msg.user_id} for msg in messages]
        return {"messages": message_list}

    # Apply the authentication decorator and rate limiting
    @token_required
    def post(self):
        data = message_parser.parse_args()
        encrypted_content = cipher_suite.encrypt(data['content'].encode()).decode()

        new_message = Message(content=encrypted_content, user_id=g.current_user.id)
        db.session.add(new_message)
        db.session.commit()

        return {"message": "Message sent successfully."}, 201

api.add_resource(Login, '/login')