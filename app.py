from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'SUPER-SECRET-KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'  # For JWT

# Initialize SQLAlchemy, Flask-RESTful, and JWTManager
db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# User Registration Resource
class UserRegistration(Resource):
    def post(self):
        data = request.get_json()

        # Validate input
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'message': 'Missing username or password'}, 400

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            return {'message': 'Username already taken'}, 400

        # Create new user
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User created successfully'}, 200

# User Login Resource
# User Login Resource
class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        
        # Extract username and password
        username = data.get('username')
        password = data.get('password')

        # Validate credentials
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            # Generate JWT access token
            access_token = create_access_token(identity=str(user.id))  # Convert user.id to a string
            return {'access_token': access_token}, 200

        return {'message': 'Invalid credentials'}, 401


# Protected Resource
class ProtectedResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        return {'message': f"Hello, user {current_user_id}. You accessed the protected resource!"}, 200

# Add resources to the API
api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(ProtectedResource, '/protected')

# Create the database tables
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
