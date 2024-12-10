from flask import Flask, jsonify, request, session, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, create_refresh_token, get_jwt_identity
import firebase_admin
from firebase_admin import credentials, firestore
import bcrypt
from datetime import timedelta
from os import environ
from dotenv import load_dotenv

load_dotenv()

#Instancia de flask
app = Flask(__name__)
app.secret_key = environ.get('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)

#Instancia de FireBase
cred = credentials.Certificate("firebase_credentials.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

jwt = JWTManager(app)

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    users_ref = db.collection('users')
    existing_user = users_ref.where('username', '==', username).get()

    if existing_user:
        return jsonify(message="El usuario ya existe.")

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user_data = {
        'username': username,
        'password': hashed_password.decode('utf-8'),
    }

    users_ref.add(user_data)
    return jsonify(message="Usuario registrado correctamente.")

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    users_ref = db.collection('users')
    users = users_ref.where('username', '==', username).get()

    if not users:
        return jsonify(message="Usuario no encontrado.")

    user = users[0].to_dict()

    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify(message="Contraseña incorrecta.")

    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    print("Access Token:", access_token)
    print("Refresh Token:", refresh_token)


    response = make_response(jsonify(message="Usuario autenticado correctamente."))
    response.set_cookie('access_token', access_token, httponly=True, secure=True, samesite='Strict', max_age=timedelta(minutes=30))
    response.set_cookie('refresh_token', refresh_token, httponly=True, secure=True, samesite='Strict', max_age=timedelta(days=7))

    session['user'] = username

    return response

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)

    response = make_response(jsonify(message="Sesión cerrada correctamente."))
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')

    return response

@app.route('/user', methods=['GET'])
@jwt_required()
def user():
    return jsonify(message="Acceso correcto.")

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    
    response = make_response(jsonify(access_token=new_access_token))
    response.set_cookie('access_token', new_access_token, httponly=True, secure=True, samesite='Strict', max_age=timedelta(minutes=30))

    return response

if __name__ == '__main__':
    app.run(debug=True)