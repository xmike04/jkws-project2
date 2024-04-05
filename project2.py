from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import serialization, asymmetric
from cryptography.hazmat.backends import default_backend
import jwt, os, uuid, base64, logging
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher


# Initialize Flask app and SQLAlchemy
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///totally_not_my_privateKeys.db'
db = SQLAlchemy(app)
ph = PasswordHasher()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the database model for storing keys
class RSAKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_data = db.Column(db.LargeBinary, nullable=False)  # Adjusted for binary storage
    expiration = db.Column(db.DateTime, nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_ip = db.Column(db.String(45), nullable=False)
    request_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    email = data['email']
    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()

    return jsonify({"password": password}), 201

def get_aes_key():
    key = os.getenv('NOT_MY_KEY')

    if key is None:
        logging.error("AES encryption key 'NOT_MY_KEY' not found in environment variables.")
        raise ValueError("AES encryption key 'NOT_MY_KEY' not found in environment variables.")

    key_bytes = key.encode()

    if len(key_bytes) not in [16, 24, 32]:
        logging.error("AES encryption key must be either 16, 24, or 32 bytes long.")
        raise ValueError("AES encryption key must be either 16, 24, or 32 bytes long.")
    return key_bytes


def encrypt_key(private_key_bytes):
    aes_gcm = AESGCM(get_aes_key())
    nonce = os.urandom(12)
    encrypted = aes_gcm.encrypt(nonce, private_key_bytes, None)
    encrypted_data = nonce + encrypted
    return base64.b64encode(encrypted_data).decode()  # Encode as base64 for storage

def decrypt_key(encrypted_key):
    aes_gcm = AESGCM(get_aes_key())
    encrypted_data = base64.b64decode(encrypted_key)  # Decode from base64
    nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
    return aes_gcm.decrypt(nonce, ciphertext, None)


# Serializes RSA keys for storage
def serialize_key(key):
    return key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()

# Deserializes stored RSA keys
def deserialize_key(key_str):
    return serialization.load_pem_private_key(key_str.encode(), None, default_backend())

# Saves keys to the database
def store_key(key, exp):
    db.session.add(RSAKey(key_data=serialize_key(key), expiration=int(exp.timestamp())))
    db.session.commit()

# Generates and stores RSA key pairs
def generate_and_store_keys():
    key_gen = lambda: asymmetric.rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    store_key(key_gen(), datetime.utcnow())
    store_key(key_gen(), datetime.utcnow() + datetime.timedelta(hours=1))

@app.route('/.well-known/jwks.json', methods=['GET'])
def serve_jwks():
    keys = RSAKey.query.filter(RSAKey.expiration > datetime.utcnow().timestamp()).all()
    jwks = {'keys': [{'kid': str(k.id), 'kty': 'RSA', 'alg': 'RS256', 'use': 'sig', 'n': deserialize_key(k.key_data).public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode().split('\n')[1], 'e': 'AQAB'} for k in keys]}
    return jsonify(jwks)

@app.route('/auth', methods=['POST'])
def authenticate_user():
    key_query = lambda exp: RSAKey.query.filter(RSAKey.expiration <= datetime.utcnow().timestamp()) if exp else RSAKey.query.filter(RSAKey.expiration > datetime.utcnow().timestamp())
    key = key_query(request.args.get('expired')).first()

    request_ip = request.remote_addr
    user = User.query.filter_by(username=request.json.get('username')).first()
    log_entry = AuthLog(request_ip=request_ip, user_id=user.id if user else None)
    db.session.add(log_entry)
    db.session.commit()

    if not key:
        return jsonify({'error': 'Key unavailable'}), 500

    try:
        user_key = deserialize_key(key.key_data)
        token = jwt.encode({'sub': 'fake_user'}, user_key, algorithm='RS256', headers={'kid': str(key.id)})
        return jsonify({'token': token})
    except Exception as e:
        return jsonify({'error': 'Failed to process authentication', 'details': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        generate_and_store_keys()
    app.run(port=8080, debug=True)
