from datetime import datetime, timedelta
from functools import wraps

from flask_socketio import SocketIO, emit

import auth
import jwt
from flask import request, jsonify, Flask, session, send_file, render_template

# Create the application instance
import certificates
from pki import generate_server_certificate

app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = 'ChatAppSecretKey'
sio = SocketIO(app, cors_allowed_origins="*")

users = {}


@sio.on('username', namespace='/private')
def receive_username(username):
    print(username)
    users[username] = request.sid
    print(users)
    print('Username added!')


@sio.on('private_message', namespace='/private')
def private_message(payload):
    recipient_session_id = users[payload['username']]
    message = payload['message']
    print(message)
    emit('private_message', message, room=recipient_session_id)
    print("message_sent")


def check_for_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers['Authorization']
        if not token:
            return jsonify({'error': 'missing token'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except Exception as e:
            print(e)
            return jsonify({'error': 'invalid token'}), 403
        return func(*args, **kwargs)

    return wrapper


@app.route('/')
def index():
    return render_template('index.html')


# Create a URL route in our application for "/"
@app.route('/login', methods=['POST'])
def login():
    if request.json["username"] and request.json["password"]:
        username = request.json["username"]
        password = request.json["password"]
        if auth.sign_in(username, password) == "Success":
            session["username"] = username
            token = jwt.encode(
                {
                    'user': username,
                    'exp': datetime.utcnow() + timedelta(minutes=700)
                },
                app.config['SECRET_KEY'],
                algorithm="HS256"
            )
            return jsonify({'token': token})
        else:
            return jsonify({"error": "login failed"})


@app.route('/register', methods=['POST'])
def sign_up():
    user = {}
    user["firstname"] = request.json["firstname"]
    user["lastname"] = request.json["lastname"]
    user["cin"] = request.json["cin"]
    user["email"] = request.json["email"]
    user["username"] = request.json["username"]
    user["password"] = request.json["password"]
    user["pubkey"] = request.json["pubkey"]
    return jsonify({"response": str(auth.subscribe(user))})


@app.route('/logout')
@check_for_token
def logout():
    session.pop('username', default=None)
    return jsonify({"response": "Logged out successfully !"})


@app.route('/<username>/certificate')
@check_for_token
def get_user_certificate(username):
    return jsonify(str(auth.get_ldap_user_certificate(username)))


@app.route('/sign', methods=['POST'])
@check_for_token
def get_signed_certificate():
    pub_key = request.json["pubkey"]
    username = request.json["username"]
    email = request.json["email"]
    return jsonify(str(certificates.generate_client_certificate(emailAddress=email, commonName=username, key=pub_key)))


@app.route('/all')
@check_for_token
def get_users():
    return jsonify(str(auth.get_ldap_users()))


@app.route('/')
def root():
    return "Hello word !"


@app.route('/auth')
@check_for_token
def authorized():
    return "Hello authed !"


# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    # app.run(ssl_context=('server_pki/cert.pem', 'server_pki/.pem'), debug=True)
    sio.run(app, port=5000)
    # sio.run(app, debug=True)
