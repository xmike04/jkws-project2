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
pip3

Installation
Clone the repository
bash
Copy code
git clone https://github.com/xmike04/jkws-project2.git
cd your-repository-name
Set up a virtual environment :
bash
Copy code:
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
run: python3 key.py to get placeholder
Install the required packages:
bash
Copy code
pip install -r requirements.txt
Set environment variables:


With the Flask application context, run the following Python commands:

python
Copy code
from yourapp import db
db.create_all()
Running the Application
To run the application on your local machine:

bash
Copy code
flask run -8080

Usage
Register a User:

bash
Copy code
curl -X POST -H "Content-Type: application/json" -d '{}' http://127.0.0.1:5000/register
Authenticate a User:

Authenticate User:
bash
Copy code
curl -X POST -H "Content-Type: application/json" -d '{


