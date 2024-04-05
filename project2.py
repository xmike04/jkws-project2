from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt, os, uuid, base64, logging
from datetime import datetime, timedelta
from argon2 import PasswordHasher

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///totally_not_my_privateKeys.db'
db = SQLAlchemy(app)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RSAKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_data = db.Column(db.LargeBinary, nullable=False)  # Storing as bytes
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

def get_aes_key():
    key = os.getenv('NOT_MY_KEY')
    if key is None:
        logging.error("AES encryption key 'NOT_MY_KEY' not found in environment variables.")
        raise ValueError("AES encryption key 'NOT_MY_KEY' not found in environment variables.")
    key_bytes = base64.urlsafe_b64decode(key)
    if len(key_bytes) not in [16, 24, 32]:
        logging.error("AES encryption key must be either 16, 24, or 32 bytes long.")
        raise ValueError("AES encryption key must be either 16, 24, or 32 bytes long.")
    return key_bytes

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    email = data['email']
    password = str(uuid.uuid4())
    ph = PasswordHasher()
    password_hash = ph.hash(password)
    user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    return jsonify({"password": password}), 201

def serialize_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_key(key_data):
    return serialization.load_pem_private_key(key_data, None, default_backend())

def store_key(key, expiration):
    db.session.add(RSAKey(key_data=serialize_key(key), expiration=expiration))
    db.session.commit()

def generate_and_store_keys():
    key_gen = lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    now = datetime.utcnow()
    store_key(key_gen(), now + timedelta(hours=1))  # Valid key
    store_key(key_gen(), now - timedelta(hours=1))  # Expired key

@app.route('/.well-known/jwks.json', methods=['GET'])
def serve_jwks():
    try:
        valid_keys = RSAKey.query.filter(RSAKey.expiration > datetime.utcnow()).all()
        jwks = {
            'keys': [{
                'kty': 'RSA',
                'use': 'sig',
                'kid': str(key.id),
                'alg': 'RS256',
                'n': base64.urlsafe_b64encode(rsa.RSAPublicNumbers(
                        e=deserialize_key(key.key_data).public_key().public_numbers().e,
                        n=deserialize_key(key.key_data).public_key().public_numbers().n
                    ).public_key(default_backend()).public_bytes(
                        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                    )).decode('utf-8'),
                'e': 'AQAB',
            } for key in valid_keys]
        }
        return jsonify(jwks)
    except Exception as e:
        logging.error(f"JWKS Endpoint Error: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/auth', methods=['POST'])
def authenticate_user():
    expired_param = request.args.get('expired', 'false').lower() == 'true'
    key_query = RSAKey.query.filter(RSAKey.expiration <= datetime.utcnow()) if expired_param else RSAKey.query.filter(RSAKey.expiration > datetime.utcnow())
    key = key_query.order_by(RSAKey.expiration.desc() if expired_param else RSAKey.expiration.asc()).first()

    if key:
        try:
            token = jwt.encode(
                {"sub": "user123"},
                deserialize_key(key.key_data),
                algorithm="RS256",
                headers={"kid": str(key.id)}
            )
            return jsonify({'token': token})
        except Exception as e:
            logging.error(f"JWT Generation Error: {str(e)}")
            return jsonify({'error': 'Failed to generate JWT'}), 500
    else:
        return jsonify({'error': 'Appropriate key not found'}), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        generate_and_store_keys()
    app.run(port=8080, debug=True)
