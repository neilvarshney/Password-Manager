from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS



BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, '..', 'frontend') 

app = Flask(__name__, template_folder=TEMPLATE_DIR)
CORS(app)

# JWT Configuration
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
JWT_SECRET_KEY = app.config['SECRET_KEY']
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 1

def generate_token(username):
    """Generate JWT token for user"""
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_token(token):
    """Verify JWT token and return username if valid"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload['username']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    """Decorator to require JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"text": "No authorization header"}), 401
        
        try:
            token = auth_header.split(' ')[1]  # Bearer <token>
        except IndexError:
            return jsonify({"text": "Invalid authorization header format"}), 401
        
        username = verify_token(token)
        if not username:
            return jsonify({"text": "Invalid or expired token"}), 401
        
        # Add username to request context
        request.current_user = username
        return f(*args, **kwargs)
    
    return decorated_function

def connect_to_local_mongodb():

    uri = "mongodb://localhost:27017/"

    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000) # 5-second timeout

        client.admin.command('ping')
        print("Successfully connected to local MongoDB at mongodb://localhost:27017/")

        return client

    except ServerSelectionTimeoutError as err:
        print(f"MongoDB connection timeout: {err}")
        print("Please ensure your MongoDB server (mongod) is running on localhost:27017.")
        return None
    
    except ConnectionFailure as err:
        print(f"MongoDB connection failed: {err}")
        print("Please check your connection string and ensure MongoDB is accessible.")
        return None
        
    except Exception as err:
        print(f"An unexpected error occurred: {err}")
        return None


class Auth():
    def __init__(self):
        self.client = connect_to_local_mongodb()
        if self.client:
            db = self.client.passwordManager
            self.collection = db.userInfo

    def createAccount(self, username, password):

        result = self.collection.find_one({"username": username})

        if result:
          error = "Account with that username already exists"
          return (False, error)
        
        else:
            salt = os.urandom(16)

            hashed_password = bcrypt.hashpw(
                password.encode('utf-8'), bcrypt.gensalt()
            ).decode('utf-8')

            document = {
                "username": username,
                "password": hashed_password,
                "salt": base64.urlsafe_b64encode(salt).decode('utf-8'),
                "websites": {}
            }

            result = self.collection.insert_one(document)
            success = "Account created successfully!"
            return True, success

    def login(self, username, password):

        result = self.collection.find_one({"username": username})

        if not result:
            error = "Invalid credentials"
            return False, error

        stored_hash = result.get("password", "").encode('utf-8')
        salt_str = result.get("salt", "")
        
        if not salt_str or not stored_hash:
            error = "Account data corrupted"
            return False, error

        try:

            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):

                success = "Login successful!"

                token = generate_token(username)
                return True, token
            
            else:
                error = "Invalid credentials"
                return False, error
            
        finally:
            # Securely wipe password from memory
            password = b'\x00' * len(password)
            


    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password))


class PasswordManager(Auth):
    def __init__(self):
        super().__init__()

    def add_password(self, username, site, password, user_password):

        result = self.collection.find_one({"username": username})
        if not result:
            error = "User not found"
            return False, error
        

        stored_hash = result.get("password", "").encode('utf-8')
        if not stored_hash:
            error = "Account data corrupted"
            return False, error
        
        if not bcrypt.checkpw(user_password.encode('utf-8'), stored_hash):
            error = "Incorrect login password"
            return False, error

        salt_str = result.get("salt", "")
        if not salt_str:
            error = "User data corrupted"
            return False, error
        
        try:
            salt = base64.urlsafe_b64decode(salt_str.encode('utf-8'))
            key = self.derive_key(user_password.encode('utf-8'), salt)
            
            password_dict = result.get("websites", {})
            encrypted = Fernet(key).encrypt(password.encode())
            password_dict[site] = encrypted.decode()

            self.collection.update_one(
                    {"username": username},
                    {"$set": {"websites": password_dict}}
            )

            success = f"Password for {site} added!"
            return True, success

        except Exception as e:
            error = f"Encryption failed: {str(e)}"
            return False, error

    def get_password(self, username, site, user_password):

        result = self.collection.find_one({"username": username})
        if not result:
            error = "User not found"
            return False, error
        
        stored_hash = result.get("password", "").encode('utf-8')
        if not stored_hash:
            error = "Account data corrupted"
            return False, error
        
        if not bcrypt.checkpw(user_password.encode('utf-8'), stored_hash):
            error = "Incorrect login password"
            return False, error
        
        website_dict = result.get("websites", {})
        if site not in website_dict:
            error = "Site not found"
            return False, error

        salt_str = result.get("salt", "")
        if not salt_str:
            error = "User data corrupted"
            return False, error
        
        encrypted_password = website_dict[site].encode()
        try:
            salt = base64.urlsafe_b64decode(salt_str.encode('utf-8'))
            key = self.derive_key(user_password.encode('utf-8'), salt)
            
            decrypted_password = Fernet(key).decrypt(encrypted_password).decode()
            success = f"Password for {site} is {decrypted_password}"
            return decrypted_password, success
        
        except Exception as e:
            error = f"Decryption failed: {str(e)}"
            return False, error



pm = PasswordManager()

@app.route('/', methods = ['GET'])
def home():
    return render_template("index.html")

@app.route('/accounts', methods=['POST'])
def create_account():
    if not request.is_json:
        return jsonify({"text": "Request must be JSON"}), 400
    try:
        data = request.get_json()
        input_username = data.get('username', '')
        input_password = data.get('password', '')
        if not input_username or not input_password:
            return jsonify({"text": "Username and password cannot be empty"}), 400
        success, message = pm.createAccount(input_username, input_password)
        if success:
            print(f"Account '{input_username}' created!")
            return jsonify({
                "status": "success",
                "original_username": input_username,
                "text": message
            }), 200
        else:
            return jsonify({
                "status": "fail",
                "text": message
            }), 409
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"text": f"Internal server error: {str(e)}"}), 500



@app.route('/sessions', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"text": "Request must be JSON"}), 400
    try:
        data = request.get_json()
        input_username = data.get('username', '')
        input_password = data.get('password', '')
        if not input_username or not input_password:
            return jsonify({"text": "Username and password cannot be empty"}), 400
        success, token = pm.login(input_username, input_password)
        if success:
            print("Successful login to " + input_username)
            return jsonify({
                "status": "success",
                "text": "Login successful!",
                "token": token
            }), 200
        else:
            print(token)
            return jsonify({
                "status": "fail",
                "text": token
            }), 401
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"text": f"Internal server error: {str(e)}"}), 500



@app.route('/passwords', methods=['POST'])
@require_auth
def add_password():
    if not request.is_json:
        return jsonify({"text": "Request must be JSON"}), 400
    try:
        data = request.get_json()
        username = request.current_user
        website = data.get('website', '')
        password = data.get('password', '')
        user_password = data.get('user_password', '')
        if not website or not password or not user_password:
            return jsonify({"text": "Website, password, and user_password cannot be empty"}), 400
        success, message = pm.add_password(username, website, password, user_password)
        if success:
            print(message)
            return jsonify({
                "status": "success",
                "text": message
            }), 200
        else:
            print(message)
            return jsonify({
                "status": "fail",
                "text": message
            }), 409
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"text": f"Internal server error: {str(e)}"}), 500



@app.route('/passwords/get', methods=['POST'])
@require_auth
def get_password():
    if not request.is_json:
        return jsonify({"text": "Request must be JSON"}), 400
    
    try:
        data = request.get_json()
        username = request.current_user
        site = data.get('site', '')
        user_password = data.get('user_password', '')

        if not site or not user_password:
            return jsonify({"text": "site and user_password cannot be empty"}), 400
        
        password, message = pm.get_password(username, site, user_password)

        if password:
            return jsonify({"status": "success", "text": message}), 200
        
        else:
            return jsonify({"status": "fail", "text": message}), 400
        
    except Exception as e:
        return jsonify({"text": f"Internal server error: {str(e)}"}), 500

        



if __name__ == "__main__":
    # Run the Flask app on http://127.0.0.1:5000
    # debug=True allows for automatic reloading on code changes
    app.run(debug = True, port = 5000)


