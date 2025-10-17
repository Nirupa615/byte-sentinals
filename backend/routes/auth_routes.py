from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

# Create blueprint
auth_bp = Blueprint('auth', __name__)

# Mock database (replace with a real database in production)
users = {}

# Secret key for JWT (in production, use a secure, unique key)
SECRET_KEY = "your-secret-key-here"

def token_required(f):
    """Decorator to verify JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            # Decode the token
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = users.get(data['public_id'])
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        except Exception as e:
            current_app.logger.error(f"Token validation error: {str(e)}")
            return jsonify({'message': 'Could not validate token'}), 500
            
        return f(current_user, *args, **kwargs)
    
    return decorated

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        # Validate input
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing username or password'
            }), 400
            
        username = data['username']
        password = data['password']
        
        # Check if user already exists
        if any(u['username'] == username for u in users.values()):
            return jsonify({
                'status': 'error',
                'message': 'Username already exists'
            }), 400
        
        # Create new user
        user_id = f"user_{len(users) + 1}"
        users[user_id] = {
            'id': user_id,
            'username': username,
            'password': generate_password_hash(password, method='pbkdf2:sha256'),
            'created_at': datetime.datetime.utcnow().isoformat(),
            'is_admin': False
        }
        
        # Generate token
        token = jwt.encode(
            {
                'public_id': user_id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        
        return jsonify({
            'status': 'success',
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'id': user_id,
                'username': username,
                'is_admin': False
            }
        }), 201
        
    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Could not register user'
        }), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login"""
    try:
        auth = request.authorization
        
        if not auth or not auth.username or not auth.password:
            return jsonify({
                'status': 'error',
                'message': 'Could not verify'
            }), 401
            
        # Find user
        user = next((u for u in users.values() if u['username'] == auth.username), None)
        
        if not user or not check_password_hash(user['password'], auth.password):
            return jsonify({
                'status': 'error',
                'message': 'Invalid credentials'
            }), 401
            
        # Generate token
        token = jwt.encode(
            {
                'public_id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        
        return jsonify({
            'status': 'success',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'is_admin': user.get('is_admin', False)
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Could not log in'
        }), 500

@auth_bp.route('/user', methods=['GET'])
@token_required
def get_current_user(current_user):
    """Get current user information"""
    return jsonify({
        'status': 'success',
        'user': {
            'id': current_user['id'],
            'username': current_user['username'],
            'is_admin': current_user.get('is_admin', False),
            'created_at': current_user.get('created_at')
        }
    })

# Protected route example
@auth_bp.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    """Example of a protected route"""
    return jsonify({
        'status': 'success',
        'message': f'Hello {current_user["username"]}! This is a protected route.'
    })
