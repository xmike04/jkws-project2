from project2 import app, db, RSAKey, User, AuthLog

def display_data():
    # Ensure the Flask app context is pushed to access the models
    with app.app_context():
        # Querying and displaying RSAKey data
        print("RSA Keys:")
        rsa_keys = RSAKey.query.all()
        for key in rsa_keys:
            print(f"ID: {key.id}, Key: {key.key_data}, Expiry: {key.expiration}")

        # Querying and displaying User data
        print("\nUsers:")
        users = User.query.all()
        for user in users:
            print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}, Registered: {user.date_registered}, Last login: {user.last_login}")

        # Querying and displaying AuthLog data
        print("\nAuthentication Logs:")
        auth_logs = AuthLog.query.all()
        for log in auth_logs:
            print(f"ID: {log.id}, Request IP: {log.request_ip}, Timestamp: {log.request_timestamp}, User ID: {log.user_id}")

if __name__ == '__main__':
    display_data()
