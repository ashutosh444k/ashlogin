from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__)

# Enable CORS
CORS(app)

# Secret Key
app.config['SECRET_KEY'] = 'super_secret_internship_key'

# Mock Database
users = []

# Home Route
@app.route('/')
def home():
    return render_template('login.html')


# ==========================================
# SIGN UP API
# ==========================================
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    if not data:
        return jsonify({"message": "No data provided"}), 400

    fullname = data.get('fullname')
    email = data.get('email')
    password = data.get('password')

    # Validation
    if not fullname or not email or not password:
        return jsonify({"message": "All fields are required"}), 400

    # Check existing user
    if any(user['email'] == email for user in users):
        return jsonify({"message": "User already exists!"}), 400

    # Hash password
    hashed_password = generate_password_hash(password)

    # Save user
    new_user = {
        "id": len(users) + 1,
        "fullname": fullname,
        "email": email,
        "password": hashed_password
    }

    users.append(new_user)
    print("Users:", users)

    return jsonify({"message": "Account created successfully!"}), 201


# ==========================================
# LOGIN API
# ==========================================
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"message": "No data provided"}), 400

    email = data.get('email')
    password = data.get('password')

    # Find user
    user = next((u for u in users if u['email'] == email), None)

    # Check user + password
    if not user or not check_password_hash(user['password'], password):
        return jsonify({"message": "Invalid email or password"}), 400

    # Generate token
    token = jwt.encode({
        'userId': user['id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    # FIX: convert bytes → string (important)
    if isinstance(token, bytes):
        token = token.decode('utf-8')

    return jsonify({
        "message": f"Welcome back, {user['fullname']}!",
        "token": token,
        "user": {
            "fullname": user['fullname'],
            "email": user['email']
        }
    }), 200


# ==========================================
# RUN SERVER
# ==========================================
if __name__ == '__main__':
    print("🚀 Flask Backend running at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)