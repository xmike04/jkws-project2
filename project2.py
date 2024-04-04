from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
import datetime
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///totally_not_my_privateKeys.db'
db = SQLAlchemy(app)

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.Text, nullable=False)
    exp = db.Column(db.Integer, nullable=False)

# Function to serialize RSA private key to PEM format
def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

# Function to save private key to the database
def save_private_key_to_db(private_key, expiry):
    serialized_key = serialize_private_key(private_key).decode()
    new_key = Key(key=serialized_key, exp=expiry)
    db.session.add(new_key)
    db.session.commit()

# Generate key pair and save to DB
def generate_key_pair_and_save():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Expire in 1 hour
    save_private_key_to_db(private_key, expiry)

with app.app_context():  # Enter Flask application context
    db.create_all()  # Create the database tables

    generate_key_pair_and_save()  # Generate and save at least one key for testing

# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    current_time = datetime.datetime.utcnow()
    valid_keys = Key.query.filter(Key.exp > current_time.timestamp()).all()

    jwks_data = {
        'keys': [
            {
                'kid': str(key.id),
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': serialization.load_pem_private_key(key.key.encode(), password=None, backend=default_backend()).public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode().split('\n')[1],
                'e': 'AQAB'
            } for key in valid_keys
        ]
    }

    return jsonify(jwks_data)

# Authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    try:
        expired_param = request.args.get('expired')

        if expired_param:
            key = Key.query.first()
        else:
            current_time = datetime.datetime.utcnow()
            key = Key.query.filter(Key.exp > current_time.timestamp()).first()

            if not key:
                return jsonify({'error': 'No valid keys available'}), 500

        private_key = serialization.load_pem_private_key(key.key.encode(), password=None, backend=default_backend())

        token_payload = {'sub': 'fake_user'}
        jwt_token = jwt.encode(token_payload, private_key, algorithm='RS256', headers={'kid': str(key.id)})

        return jsonify({'token': jwt_token})
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Internal Server Error'}), 500

if __name__ == '__main__':
    app.run(port=8080, debug=True)
