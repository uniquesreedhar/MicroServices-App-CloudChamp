import jwt
import datetime
import os
from flask import Flask, request

server = Flask(__name__)

@server.route('/login', methods=['POST'])
def login():
    hardcoded_username = "madithatisreedhar123@gmail.com"
    hardcoded_password = "sree@123"

    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return 'Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}

    if auth.username != hardcoded_username or auth.password != hardcoded_password:
        return 'Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}
    else:
        return create_jwt_token(auth.username, os.environ['JWT_SECRET'], True)

def create_jwt_token(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1),
            "iat": datetime.datetime.now(tz=datetime.timezone.utc),
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )

@server.route('/validate', methods=['POST'])
def validate():
    encoded_jwt = request.headers.get('Authorization')

    if not encoded_jwt:
        return 'Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}

    encoded_jwt = encoded_jwt.split(' ')[1]
    try:
        decoded_jwt = jwt.decode(encoded_jwt, os.environ['JWT_SECRET'], algorithms=["HS256"])
    except:
        return 'Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}

    return decoded_jwt, 200

if __name__ == '__main__':
    server.run(host='0.0.0.0', port=5000)

