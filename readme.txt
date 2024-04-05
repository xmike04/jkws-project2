Flask Authentication and Key Management API
This Flask application provides a robust authentication system, secure key management for JWT signing, and user registration with hashed passwords. It's designed to demonstrate secure practices in handling encryption keys, user credentials, and logging authentication attempts.

Features
User Registration: Securely register users with automatically generated passwords.
Authentication: Authenticate users and return a JWT for authorized access.
Key Management: Manage JWT signing keys with AES encryption, ensuring they are securely stored.
Logging: Log authentication attempts, including requester's IP and timestamp.
Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

Prerequisites
Python 3.6+
pip

Installation
Clone the repository
bash
Copy code
git clone https://github.com/xmike04/jkws-project2.git
cd your-repository-name
Set up a virtual environment (optional but recommended):
bash
Copy code
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
Install the required packages:
bash
Copy code
pip install -r requirements.txt
Set environment variables:
Set the NOT_MY_KEY environment variable for AES encryption. This key must be 16, 24, or 32 bytes long.

On Linux/macOS:

bash
Copy code
export NOT_MY_KEY='your_aes_encryption_key_here'
On Windows:

cmd
Copy code
set NOT_MY_KEY=your_aes_encryption_key_here
Initialize the database:
With the Flask application context, run the following Python commands:

python
Copy code
from yourapp import db
db.create_all()
Running the Application
To run the application on your local machine:

bash
Copy code
flask run
The application will be available at http://127.0.0.1:5000/.

Usage
Register a User:

bash
Copy code
curl -X POST -H "Content-Type: application/json" -d '{}' http://127.0.0.1:5000/register
Authenticate a User:

bash
Copy code
curl -X POST -H "Content-Type: application/json" -d '{


Acknowledgments
Flask for the minimalist web framework.
PyJWT, Argon2, and Cryptography libraries for handling JWTs, password hashing, and encryption.
