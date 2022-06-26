#Flask Boilerplate

import flask
from flask import Flask, request, jsonify, make_response
import jwt
import json
import bcrypt
import os
from functools import wraps
from flask_sqlalchemy import SQLAlchemy

#initialize flask app
app = Flask(__name__)

#configure flask app
app.config['SECRET_KEY'] = 'thisisasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

#initialize database
db = SQLAlchemy(app)

#create user table
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

#function to generate token
def generate_token(user):
    try:
        #create payload
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow(),
            'sub': user.id
        }
        #create token with payload and config key
        token = jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )
        return token
    except Exception as e:
        return str(e)

#function to verify token
def verify_token(token):
    try:
        #try to decode token using config key
        payload = jwt.decode(token, app.config.get('SECRET_KEY'))
        return payload['sub']
    except jwt.ExpiredSignatureError:
        #the token has expired, return an error string
        return "Expired token. Please login to get a new token"
    except jwt.InvalidTokenError:
        #the token is invalid, return an error string
        return "Invalid token. Please register or login"

#function to check if user is logged in
def logged_in(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        #check for token in headers
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        #if no token in headers, check for token in cookies
        if not token and 'access_token' in request.cookies:
            token = request.cookies.get('access_token')
        if not token:
            #if no token was found, return error
            return jsonify({'message' : 'Token is missing!'}), 403
        try:
            #try to verify the token
            data = verify_token(token)
        except Exception as e:
            #if there was an error verifying the token, return error
            return jsonify({'message' : str(e)}), 403
        return f(*args, **kwargs)
    return decorated

#create an endpoint for registering a user
@app.route('/register', methods=['POST'])
def register():
    #get form data
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    #hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    #create user
    new_user = User(name=name, email=email, password=hashed_password)
    #add user to database
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message' : 'New user created!'})

#create an endpoint for logging in a user
@app.route('/login', methods=['POST'])
def login():
    #get form data
    email = request.form['email']
    password = request.form['password']
    #get user from database
    user = User.query.filter_by(email=email).first()
    #if user doesn't exist, return error
    if not user:
        return jsonify({'message' : 'Invalid email'}), 403
    #if user exists, check password
    if bcrypt.checkpw(password.encode('utf-8'), user.password):
        #generate token
        token = generate_token(user)
        #if token is generated, return token
        return jsonify({'token' : token.decode('UTF-8')})
    #if password is incorrect, return error
    else:
        return jsonify({'message' : 'Incorrect password'}), 403

#create an endpoint for getting all users
@app.route('/users', methods=['GET'])
@logged_in
def get_all_users():
    #get all users from database
    users = User.query.all()
    output = []
    #loop through users
    for user in users:
        #get user data
        user_data = {}
        user_data['id'] = user.id
        user_data['name'] = user.name
        user_data['email'] = user.email
        #append user data to output
        output.append(user_data)
    return jsonify({'users' : output})

#create an endpoint for getting one user
@app.route('/user/<user_id>', methods=['GET'])
@logged_in
def get_one_user(user_id):
    #get user from database
    user = User.query.filter_by(id=user_id).first()
    #if user doesn't exist, return error
    if not user:
        return jsonify({'message' : 'User does not exist'}), 403
    #if user exists, return user data
    user_data = {}
    user_data['id'] = user.id
    user_data['name'] = user.name
    user_data['email'] = user.email
    return jsonify({'user' : user_data})

@app.route('/docs')
def docs():
    #generate documentation
    docs = {}
    #get all users
    users = User.query.all()
    #loop through users
    for user in users:
        #get user data
        user_data = {}
        user_data['id'] = user.id
        user_data['name'] = user.name
        user_data['email'] = user.email
        #append user data to docs
        docs[user.id] = user_data
    #get all endpoints
    endpoints = {}
    for rule in app.url_map.iter_rules():
        #get endpoint data
        endpoint_data = {}
        endpoint_data['methods'] = ','.join(rule.methods)
        endpoint_data['url'] = rule.rule
        #append endpoint data to docs
        endpoints[rule.rule] = endpoint_data
    return jsonify({'docs' : docs, 'endpoints' : endpoints}) 

#run flask app
if __name__ == '__main__':
    app.run()
