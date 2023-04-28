from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from resources import Register, Login, Messages
from flask_jwt_extended import JWTManager

# Initialize Flask app
app = Flask(__name__)
# Enable Cross-Origin Resource Sharing (CORS) for the app
CORS(app)
# Initialize rate limiting
limiter = Limiter(app)

# Configure app settings
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_messaging.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with your own secret key

# Initialize database and migration tools
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize the RESTful API
api = Api(app)

# Initialize JWTManager for handling JWT authentication
jwt = JWTManager(app)

# Apply rate limiting on the messages resource
limiter.limit("50/minute")(Messages)

# Register resources and routes
api.add_resource(Register, '/api/register')
api.add_resource(Login, '/api/login')
api.add_resource(Messages, '/api/messages')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
