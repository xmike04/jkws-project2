from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import serialization, asymmetric
from cryptography.hazmat.backends import default_backend
import jwt, datetime

# Initialize Flask app and SQLAlchemy
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///totally_not_my_privateKeys.db'
db = SQLAlchemy(app)

# Define the database model for storing keys
class RSAKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_data = db.Column(db.Text, not_null=True)
    expiration = db.Column(db.Integer, not_null=True)

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
    store_key(key_gen(), datetime.datetime.utcnow())
    store_key(key_gen(), datetime.datetime.utcnow() + datetime.timedelta(hours=1))

@app.route('/.well-known/jwks.json', methods=['GET'])
def serve_jwks():
    keys = RSAKey.query.filter(RSAKey.expiration > datetime.datetime.utcnow().timestamp()).all()
    jwks = {'keys': [{'kid': str(k.id), 'kty': 'RSA', 'alg': 'RS256', 'use': 'sig', 'n': deserialize_key(k.key_data).public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode().split('\n')[1], 'e': 'AQAB'} for k in keys]}
    return jsonify(jwks)

@app.route('/auth', methods=['POST'])
def authenticate_user():
    key_query = lambda exp: RSAKey.query.filter(RSAKey.expiration <= datetime.datetime.utcnow().timestamp()) if exp else RSAKey.query.filter(RSAKey.expiration > datetime.datetime.utcnow().timestamp())
    key = key_query(request.args.get('expired')).first()

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
