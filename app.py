from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime

app = Flask(__name__)

# ==========================================
# CONFIG
# ==========================================

CORS(app)

app.config['SECRET_KEY'] = 'super_secret_dashboard_key'
app.config['SESSION_TYPE'] = 'filesystem'

# ==========================================
# MOCK DATABASE
# ==========================================

users = []

# ==========================================
# AUTH DECORATOR
# ==========================================

def token_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        # Check token from headers
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        # Check token from session
        if not token and 'token' in session:
            token = session['token']

        if not token:
            return jsonify({
                "message": "Token is missing"
            }), 401

        try:

            data = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms=["HS256"]
            )

            current_user = next(
                (u for u in users if u['id'] == data['userId']),
                None
            )

            if not current_user:
                return jsonify({
                    "message": "User not found"
                }), 401

        except jwt.ExpiredSignatureError:

            return jsonify({
                "message": "Token expired"
            }), 401

        except jwt.InvalidTokenError:

            return jsonify({
                "message": "Invalid token"
            }), 401

        return f(current_user, *args, **kwargs)

    return decorated

# ==========================================
# HOME ROUTE
# ==========================================

@app.route('/')
def home():

    if 'token' in session:
        return redirect(url_for('dashboard_page'))

    return render_template('login.html')

# ==========================================
# DASHBOARD PAGE
# ==========================================

@app.route('/dashboard')
def dashboard_page():

    token = session.get('token')

    if not token:
        return redirect(url_for('home'))

    try:

        data = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            algorithms=["HS256"]
        )

        current_user = next(
            (u for u in users if u['id'] == data['userId']),
            None
        )

        if not current_user:
            return redirect(url_for('home'))

        return render_template(
            'dashboard.html',
            user=current_user
        )

    except:
        return redirect(url_for('home'))

# ==========================================
# DASHBOARD API
# ==========================================

@app.route('/api/dashboard', methods=['GET'])
@token_required
def get_dashboard_data(current_user):

    dashboard_data = {

        "user": {
            "fullname": current_user['fullname'],
            "email": current_user['email']
        },

        "stats": {
            "total_visits": 42,
            "projects_completed": 8,
            "internship_days": 45,
            "achievements": 3
        },

        "recent_activity": [
            {
                "date": "2026-05-20",
                "activity": "Completed login system",
                "type": "coding"
            },
            {
                "date": "2026-05-19",
                "activity": "Created dashboard UI",
                "type": "feature"
            },
            {
                "date": "2026-05-18",
                "activity": "Fixed authentication issue",
                "type": "debug"
            },
            {
                "date": "2026-05-17",
                "activity": "Started internship project",
                "type": "feature"
            }
        ],

        "notifications": [
            {
                "id": 1,
                "message": "Welcome to your dashboard!",
                "type": "success"
            },
            {
                "id": 2,
                "message": "Profile setup completed",
                "type": "info"
            },
            {
                "id": 3,
                "message": "New features available",
                "type": "info"
            }
        ]
    }

    return jsonify(dashboard_data), 200

# ==========================================
# SIGNUP API
# ==========================================

@app.route('/signup', methods=['POST'])
def signup():

    data = request.get_json()

    if not data:
        return jsonify({
            "message": "No data provided"
        }), 400

    fullname = data.get('fullname')
    email = data.get('email')
    password = data.get('password')

    # Validation
    if not fullname or not email or not password:

        return jsonify({
            "message": "All fields are required"
        }), 400

    # Check existing user
    if any(user['email'] == email for user in users):

        return jsonify({
            "message": "User already exists"
        }), 400

    # Hash password
    hashed_password = generate_password_hash(password)

    # Save User
    new_user = {
        "id": len(users) + 1,
        "fullname": fullname,
        "email": email,
        "password": hashed_password
    }

    users.append(new_user)

    print("Users:", users)

    return jsonify({
        "message": "Account created successfully"
    }), 201

# ==========================================
# LOGIN API
# ==========================================

@app.route('/login', methods=['POST'])
def login():

    data = request.get_json()

    if not data:

        return jsonify({
            "message": "No data provided"
        }), 400

    email = data.get('email')
    password = data.get('password')

    # Find user
    user = next(
        (u for u in users if u['email'] == email),
        None
    )

    # Validate
    if not user or not check_password_hash(
        user['password'],
        password
    ):

        return jsonify({
            "message": "Invalid email or password"
        }), 400

    # Generate JWT Token
    token = jwt.encode({

        'userId': user['id'],

        'exp': datetime.datetime.utcnow()
        + datetime.timedelta(hours=24)

    },
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )

    # Convert bytes → string
    if isinstance(token, bytes):
        token = token.decode('utf-8')

    # Save token in session
    session['token'] = token

    return jsonify({

        "message": f"Welcome back, {user['fullname']}!",

        "token": token,

        "user": {
            "fullname": user['fullname'],
            "email": user['email']
        }

    }), 200

# ==========================================
# FORGOT PASSWORD
# ==========================================

@app.route('/forgot-password', methods=['POST'])
def forgot_password():

    data = request.get_json()

    email = data.get('email')

    user = next(
        (u for u in users if u['email'] == email),
        None
    )

    if not user:

        return jsonify({
            "message":
            "If account exists, reset instructions will be sent."
        }), 200

    return jsonify({
        "message": "Password reset link sent successfully"
    }), 200

# ==========================================
# LOGOUT
# ==========================================

@app.route('/logout', methods=['POST'])
def logout():

    session.pop('token', None)

    return jsonify({
        "message": "Logged out successfully"
    }), 200

# ==========================================
# RUN SERVER
# ==========================================

if __name__ == '__main__':

    print("🚀 Flask server running at http://127.0.0.1:5000")

    app.run(
        debug=True,
        port=5000
    )
