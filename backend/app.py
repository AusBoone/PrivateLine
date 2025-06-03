"""Application factory and global objects for the backend."""

import os
from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO
from dotenv import load_dotenv

# Load environment variables from a .env file if present.  This keeps
# secret values such as JWT_SECRET_KEY out of source control.
load_dotenv()

# Initialize Flask app and extensions
app = Flask(__name__)

# Enable Cross-Origin Resource Sharing (CORS) for the app
CORS(app)

# SocketIO is used for pushing real-time updates to connected clients
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize rate limiting
limiter = Limiter(app)

# Configure app settings. Values can be overridden via environment variables.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URI', 'sqlite:///secure_messaging.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'change-me')

# Initialize database and migration tools
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize the RESTful API
api = Api(app)

# Initialize JWTManager for handling JWT authentication
jwt = JWTManager(app)

# Import resources after initializing app components to avoid circular imports
from .resources import Register, Login, Messages, PublicKey

# Apply rate limiting on the messages resource
limiter.limit("50/minute")(Messages)

# Register resources and routes
api.add_resource(Register, '/api/register')
api.add_resource(Login, '/api/login')
api.add_resource(Messages, '/api/messages')
api.add_resource(PublicKey, '/api/public_key/<string:username>')

# Run the development server only when executed directly.
if __name__ == '__main__':
    # socketio.run enables WebSocket support alongside the Flask app
    socketio.run(app, debug=True)
